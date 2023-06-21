"""This containst functions to reverse secrets from traces. """
import logging
import angr
from copy import copy
logger = logging.getLogger(__name__)
info = logger.info
debug = logger.debug

def reverse(simgr, infile, kind="inst", **kwargs):
    """Reverses the secret from the trace. Returns the simgr.
    The reason why we use the simgr instead of state is because we want to have a specific ExplorationTechnique.
    """

    info("Reading trace from %s", infile)
    with open(infile, "r") as f:
        traces = [int(line, 16) for line in f]

    simgr = simgr.copy()
    if kind == "inst":
        return _reverse_inst(simgr, traces, **kwargs)
    elif kind == "mem":
        return _reverse_mem(simgr, traces, **kwargs)
    else:
        raise ValueError(f"Unknown reverse kind {kind}")


def _reverse_inst(simgr, traces, **kwargs):
    """
    Reverses the state by comparing the executed instructions to the trace. Returns the simgr.
    """
    # Implement as a ExplorationTechnique to be able to use **kwargs
    assert len(simgr.active) == 1, "Only one active state is supported"
    if len(kwargs) > 0:
        raise NotImplementedError("Unknown arguments: %s" % kwargs.keys())

    callstack_size = len(simgr.active[0].callstack)

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
    return simgr.found[0]

def _reverse_inst_from_incomplete(simgr, traces, **kwargs):
    """
    Reverses the state by comparing the executed instructions to the trace. Returns the simgr.
    """
    # Implement as a ExplorationTechnique to be able to use **kwargs
    assert len(simgr.active) == 1, "Only one active state is supported"
    if len(kwargs) > 0:
        raise NotImplementedError("Unknown arguments: %s" % kwargs.keys())

    callstack_size = len(simgr.active[0].callstack)

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
    return simgr.found[0]

def _reverse_mem(simgr, traces, **kwargs):

    if "find" not in kwargs:
        callstack_size = len(simgr.active[0].callstack)
        
        def find(state):
            return len(state.callstack) < callstack_size
    else:
        find = kwargs["find"]

    simgr.active[0].options.add(angr.options.TRACK_MEMORY_ACTIONS)

    debug("Exploring until %s", find)
    simgr.explore(find=find)
    debug("Exploration complete")
    
    # Reverse the secret from the trace

    # Create s new solver instance since the state.solver is pollued with constraints
    # from the memory accesses
    proj = simgr.found[0].project
    state = proj.factory.blank_state()
    
    # Add constraints from the trace
    for action in simgr.found[0].history.actions:
        if action.type == "mem":
            debug("Adding constraint %s == 0x%x", action.addr, traces[0])
            state.add_constraints(action.addr == traces.pop(0))

    return state.copy()
