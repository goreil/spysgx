import angr, claripy
from pwn import *
import logging
import json
binary = "./sqr_mlt"
proj = angr.Project(binary, auto_load_libs=False)
elf = ELF(binary)

def symbolic_reverse_with_trace(base, prime, target, tracefile="trace.txt", bound = None):

    if tracefile is not None:
        with open(tracefile) as f:
            trace = json.load(f)
    
    exponent = claripy.BVS('exponent', 64 * 8)
    state = proj.factory.blank_state(addr = elf.sym['square_mult'])
    state.regs.rdi = base
    state.regs.rsi = exponent
    state.regs.rdx = prime
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)

    if bound is not None:
        state.solver.add(exponent < bound)

    simgr = proj.factory.simgr(state)

    state.globals["current_block"] = 0

    def done(state):
        """Returns True if rax == target"""
        return state.solver.eval(state.regs.rax) == target

    def impossible(state):
        """Returns False if the current state is impossible by comparing the executed instructions to the trace"""
        if tracefile is None:
            return False

        i = state.globals["current_block"]
        if i == len(trace):
            return False
        return i > len(trace) or trace[i] != state.addr

    # Set the global variable executed_instructions to 0
    simgr.found = []
    while len(simgr.active) > 0 and len(simgr.found) < 1:
        while len(simgr.errored) > 0:
            state = simgr.errored.pop().state
            if done(state):
                simgr.found.append(state)
        simgr.move(from_stash="active", to_stash="avoid", filter_func=impossible)
        for s in simgr.active:
            s.globals["current_block"] += 1

        simgr.step()

    if simgr.found:
        state = simgr.found[0]
    elif simgr.errored:
        state = simgr.errored[0].state
    secret_exponent = state.solver.eval(exponent)
    print("Secret exponent =", secret_exponent)

    assert pow(base, secret_exponent, prime) == target
    return secret_exponent


if __name__ == "__main__":
    tracefile = "trace.txt"
    target = 7366502228419431053
    logging.getLogger("angr").setLevel("INFO")
    symbolic_reverse_with_trace(target, None, 2 ** 10)