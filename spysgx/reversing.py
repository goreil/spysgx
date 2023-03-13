"""This containst functions to reverse secrets from traces. """
import logging
import angr
logger = logging.getLogger(__name__)
info = logger.info

def reverse(simgr, infile, kind="inst", **kwargs):
    """Reverses the secret from the trace. Returns the simgr.
    The reason why we use the simgr instead of state is because we want to have a specific ExplorationTechnique.
    """
    # TODO load the trace from the file

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
    return simgr.found[0].solver

def _reverse_mem(simgr, traces, **kwargs):

    if "find" not in kwargs:
        callstack_size = len(simgr.active[0].callstack)
        
        def find(state):
            return len(state.callstack) < callstack_size
    else:
        find = kwargs["find"]

    simgr.active[0].options.add(angr.options.TRACK_MEMORY_ACTIONS)

    simgr.explore(find=find)
    
    # Reverse the secret from the trace
    state = simgr.found[0]
    # Create s new solver instance since the state.solver is pollued with constraints
    # from the memory accesses
    proj = state.project
    solver = proj.factory.blank_state().solver
    for action in state.history.actions:
        if action.type == "mem":
            solver.add(action.addr == traces.pop(0))

    return solver 
