import logging
import angr
import guardian
import os
import pickle
import re

from .explorer import EnclaveExploration

logger = logging.getLogger(__name__)
info, debug = logger.info, logger.debug


class Project:
    """
    The Project class creates a spySGX project from an enclave and a target ecall.

    Parameters
    ----------
    enclave_path : str
        Path to the enclave
    target_ecall : str
        Name of the target ecall
    pickle_path : str
        Path to the pickle file, where the project is cached for later use
    """
    def __init__(self, enclave_path, target_ecall, pickle_path = None, base_addr=0x400000,
    ):
        # Load the project from a pickle file if it exists
        self.proj = angr.Project(
            enclave_path, load_options={"main_opts": {"base_addr": base_addr}}
        )

        # [HACK] TODO Current hack before we have the correct SGX-SDK
        self.proj.hook_symbol("sgx_is_outside_enclave", angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"]())
        # [Hack end]

        self.guard = guardian.Project(
            self.proj,
            find_missing_ecalls_or_ocalls=True,
            violation_check=False,
        )
        # Set the correct target ecall
        ecall_id = None
        for ecall in self.guard.ecalls:
            if ecall[1] == target_ecall:
                ecall_id = ecall[0]
                break
        
        assert ecall_id is not None, f"Could not find ecall {target_ecall}"
        self.guard.set_target_ecall(ecall_id)
        
        # Use a custom exploration technique to print out the current symbol for debugging
        self.guard.simgr.use_technique(EnclaveExploration())

        self.traces = None # Will be set by dump_trace
        ecall_name = re.match(r"^sgx_(.*)", target_ecall).group(1)
        self._reach_symbol(ecall_name)

        # Save the project to a pickle file
        if pickle_path is not None:
            with open(pickle_path, "wb+") as f:
                pickle.dump(self, f)
            info(f"Saved project to {pickle_path}")


    def _reach_symbol(self, find):
        """Try to reach a symbol with guardian."""
        simgr = self.guard.simgr
        # Avoid is a nice way to just call a function if that function is always false
        simgr.explore(find=self.proj.loader.find_symbol(find).rebased_addr)
        simgr.move(from_stash="active", to_stash="discarded")
        simgr.move(from_stash="found", to_stash="active")
        # Clear the history.bbl_addrs
        simgr.active[0].history.trim()

        return simgr

    def dump_trace(self, outfile, kind="inst"):
        simgr = self.guard.simgr.copy()
        assert len(simgr.active) == 1, "Only one active state is supported"
        callstack_size = len(simgr.active[0].callstack)
      
        def done(state):
            return len(state.callstack) < callstack_size
        if kind == "inst":
            self._collect_trace_instructions(simgr, done)
        
        elif kind == "mem":
            self._collect_trace_memory(simgr, done)

        with open(outfile, "w+") as f:
            f.write("\n".join([hex(addr) for addr in self.traces]))
        info("Wrote trace to %s", outfile)

        return simgr

    def _collect_trace_memory(self, simgr, done):
        simgr.active[0].options.add(angr.options.TRACK_MEMORY_ACTIONS)

        simgr.explore(find=done)
        # With the TRACK_MEMORY_ACTIONS option, the history.actions will contain all the memory actions
        state = simgr.found[0]
        trace = state.history.actions
        self.traces = [state.solver.eval(trace.addr) for trace in trace if trace.type == "mem"]

    def _collect_trace_instructions(self, simgr, done):
        """Dumps the trace to a file. Returns the simgr."""
        
        # Reach the place where the function returns
        simgr.explore(find=done)

        # Backtrace the basic block addresses
        trace = simgr.found[0].history.bbl_addrs 
        # Join all instruction addresses together
        self.traces = sum(
            [list(self.proj.factory.block(addr).instruction_addrs) for addr in trace],
            [],
        )
        # Remove first instruction since it is the call
        self.traces = self.traces[1:]

    def reverse_trace(self, infile):
        """Reverses the state by comparing the executed instructions to the trace. Returns the simgr."""
        simgr = self.guard.simgr.copy()
        assert len(simgr.active) == 1, "Only one active state is supported"
        callstack_size = len(simgr.active[0].callstack)

        def done(state):
            return len(state.callstack) < callstack_size

        def impossible(state):
            """Returns False if the current state is impossible by comparing the executed instructions to the trace"""
            i = state.globals["executed_instructions"]
            instructions = list(state.block().instruction_addrs)
            # state.globals['executed_instructions'] += len(instructions)
            return instructions != self.traces[i : i + len(instructions)]

        info("Reading trace from %s", infile)
        with open(infile, "r") as f:
            self.traces = [int(line, 16) for line in f]
        info("Done")

        # Set the global variable executed_instructions to 0
        simgr.active[0].globals["executed_instructions"] = 0
        while len(simgr.found) < 1 and len(simgr.active) > 0:
            simgr.move(
                from_stash="active",
                to_stash="found",
                filter_func=lambda s: len(s.callstack) < callstack_size,
            )
            simgr.move(from_stash="active", to_stash="avoid", filter_func=impossible)
            for s in simgr.active:
                s.globals["executed_instructions"] += s.block().instructions

            simgr.step()
        return simgr
