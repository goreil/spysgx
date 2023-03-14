"""This file contains functions to collect traces """

import logging
import angr

logger = logging.getLogger(__name__)
info = logger.info


def _collect_trace_memory(state):
    actions = state.history.actions
    traces = [state.solver.eval(trace.addr) for trace in actions if trace.type == "mem"]
    return traces

def _collect_trace_instructions(state):
    proj = state.project
    # Backtrace the basic block addresses
    bbl_addrs = state.history.bbl_addrs 
    # Join all instruction addresses together
    traces = sum(
        [list(proj.factory.block(addr).instruction_addrs) for addr in bbl_addrs],
        [],
    )
    # Remove first instruction since it is the call
    traces = traces[1:]
    return traces

def trace(simgr, outfile, kind="inst", until_return=True, **kwargs):
    """Dumps the trace to a file. Returns the simgr."""
    setup = {
        "mem": {"TRACK_MEMORY_ACTIONS"},
        "inst": set(),
    }

    tracefunc = {
        "mem": _collect_trace_memory,
        "inst": _collect_trace_instructions,
    }

    if kind not in ["inst", "mem"]:
        raise ValueError(f"Unknown trace kind {kind}")

    simgr = simgr.copy()
    assert len(simgr.active) == 1, "Only one active state is supported"
    callstack_size = len(simgr.active[0].callstack)

    for options in setup[kind]: 
        simgr.active[0].options.add(options)

    if until_return:
        simgr.explore(find=lambda s: len(s.callstack) < callstack_size, **kwargs)
    else:
        simgr.explore(**kwargs)

    if len(simgr.found) > 0:
        state = simgr.found[0]
    else:
        state = simgr.deadended[0]

    out = tracefunc[kind](state)

    with open(outfile, "w+") as f:
        f.write("\n".join([hex(addr) for addr in out]))
    info("Wrote trace to %s", outfile)

    return simgr

