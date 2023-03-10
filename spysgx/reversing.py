"""This containst functions to reverse secrets from traces. """
import logging
logger = logging.getLogger(__name__)
info = logger.info

def reverse_trace(simgr, infile):
    """Reverses the state by comparing the executed instructions to the trace. Returns the simgr."""
    assert len(simgr.active) == 1, "Only one active state is supported"
    callstack_size = len(simgr.active[0].callstack)

    info("Reading trace from %s", infile)
    with open(infile, "r") as f:
        traces = [int(line, 16) for line in f]

    def done(state):
        return len(state.callstack) < callstack_size

    def impossible(state):
        """Returns False if the current state is impossible by comparing the executed instructions to the trace"""
        i = state.globals["executed_instructions"]
        instructions = list(state.block().instruction_addrs)
        return instructions != traces[i : i + len(instructions)]

    # Set the global variable executed_instructions to 0
    simgr.active[0].globals["executed_instructions"] = 0
    while len(simgr.found) < 1 and len(simgr.active) > 0:
        simgr.move(
            from_stash="active",
            to_stash="found",
            filter_func=done
        )
        simgr.move(from_stash="active", to_stash="avoid", filter_func=impossible)
        for s in simgr.active:
            s.globals["executed_instructions"] += s.block().instructions

        simgr.step()
    return simgr