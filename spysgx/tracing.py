"""This file contains functions to collect traces """

import logging
import angr

logger = logging.getLogger(__name__)
info = logger.info

def trace(simgr, outfile, kind="inst"):
    """Dumps the trace to a file. Returns the simgr."""
    assert len(simgr.active) == 1, "Only one active state is supported"
    callstack_size = len(simgr.active[0].callstack)
    
    def done(state):
        return len(state.callstack) < callstack_size
    if kind == "inst":
        trace = _collect_trace_instructions(simgr, done)
    
    elif kind == "mem":
        trace = _collect_trace_memory(simgr, done)
    
    else:
        raise ValueError(f"Unknown trace kind {kind}")

    with open(outfile, "w+") as f:
        f.write("\n".join([hex(addr) for addr in trace]))
    info("Wrote trace to %s", outfile)

    return simgr


def _collect_trace_memory(simgr, done):
    simgr.active[0].options.add(angr.options.TRACK_MEMORY_ACTIONS)

    simgr.explore(find=done)
    # With the TRACK_MEMORY_ACTIONS option, the history.actions will contain all the memory actions
    state = simgr.found[0]
    trace = state.history.actions
    traces = [state.solver.eval(trace.addr) for trace in trace if trace.type == "mem"]
    return traces


def _collect_trace_instructions(simgr, done):
    proj = simgr.active[0].project
    # Reach the place where the function returns
    simgr.explore(find=done)

    # Backtrace the basic block addresses
    trace = simgr.found[0].history.bbl_addrs 
    # Join all instruction addresses together
    traces = sum(
        [list(proj.factory.block(addr).instruction_addrs) for addr in trace],
        [],
    )
    # Remove first instruction since it is the call
    traces = traces[1:]
    return traces
