import logging
import angr
import guardian

from .explorer import EnclaveExploration

logger = logging.getLogger(__name__)
info, debug = logger.info, logger.debug


class Project:
    def __init__(
        self,
        enclave_path,
        ecalls=None,
        find_missing_ecalls_or_ocalls=True,
        base_addr=0x400000,
    ):
        """Initialize the project and the guardian object. Set the state options for the entry state."""
        self.proj = angr.Project(
            enclave_path, load_options={"main_opts": {"base_addr": base_addr}}
        )

        # [HACK] TODO Current hack before we have the correct SGX-SDK
        class SIM_FALSE(angr.SimProcedure):
            def run(self, argc, argv):
                return 1

        self.proj.hook_symbol("sgx_is_outside_enclave", SIM_FALSE())
        # [Hack end]

        self.guard = guardian.Project(
            self.proj,
            find_missing_ecalls_or_ocalls=find_missing_ecalls_or_ocalls,
            violation_check=False,
        )

        # Use a custom exploration technique to print out the current symbol for debugging
        self.guard.simgr.use_technique(EnclaveExploration())

    def reach_symbol(self, find):
        """Try to reach a symbol with guardian."""
        simgr = self.guard.simgr
        # Avoid is a nice way to just call a function if that function is always false
        simgr.explore(find=self.proj.loader.find_symbol(find).rebased_addr)
        simgr.move(from_stash="active", to_stash="discarded")
        simgr.move(from_stash="found", to_stash="active")
        # Clear the history.bbl_addrs
        simgr.active[0].history.trim()

        return simgr

    def dump_trace(self, outfile):
        simgr = self.guard.simgr.copy()
        assert len(simgr.active) == 1, "Only one active state is supported"
        callstack_size = len(simgr.active[0].callstack)

        def done(state):
            return len(state.callstack) < callstack_size

        # Reach the place where the function returns
        simgr.explore(find=done)

        info("Writing trace to %s", outfile) 
        # Backtrace the basic block addresses
        trace = simgr.found[0].history.bbl_addrs 
        # Join all instruction addresses together
        self.traces = sum(
            [list(self.proj.factory.block(addr).instruction_addrs) for addr in trace],
            [],
        )
        # Remove first instruction since it is the call
        self.traces = self.traces[1:]
        with open(outfile, "w") as f:
            f.write("\n".join([hex(addr) for addr in self.traces]))
        info("Write trace to %s", outfile)

        return simgr

    def reverse_trace(self, infile):
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
