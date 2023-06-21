import angr, claripy
from pwn import *
binary = "./sqr_mlt"
proj = angr.Project(binary, auto_load_libs=False)
elf = ELF(binary)


def trace(base, prime, exponent, tracefile = "trace.txt"):
    state = proj.factory.blank_state(addr = elf.sym['square_mult'])
    state.regs.rdi = base
    state.regs.rsi = exponent
    state.regs.rdx = prime
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)

    simgr = proj.factory.simgr(state)
    simgr.run()
    if simgr.errored:
        state = simgr.errored[0].state
    else:
        state = simgr.found[0].state


    out = state.solver.eval(state.regs.rax)
    assert out == pow(base, exponent, prime)

    with open("trace.txt", "w") as f:
        f.write(str(state.history.bbl_addrs.hardcopy))
    
    return out

if __name__ == "__main__":
    trace(0x10001)
    print("Done")