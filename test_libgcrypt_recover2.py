
import angr
import logging
from tqdm import tqdm

DEBUG_LEVEL = logging.WARN

logger = logging.getLogger("angr")
logger.setLevel(DEBUG_LEVEL)
proj = angr.Project("enclaves/libgcrypt.so")
addr = proj.loader.find_symbol("_gcry_mpi_invm").rebased_addr
types = angr.types.parse_type("""

struct gcry_mpi
{
  int alloced;         /* Array size (# of allocated limbs). */
  int nlimbs;          /* Number of valid limbs. */
  int sign;

  unsigned int flags; /* Bit 0: Array to be allocated in secure memory space.*/
                      /* Bit 2: The limb is a pointer to some m_alloced data.*/
                      /* Bit 4: Immutable MPI - the MPI may not be modified.  */
                      /* Bit 5: Constant MPI - the MPI will not be freed.  */
  unsigned long int *d;      /* Array with the limbs */
}
""")
angr.types.register_types(types)
state = proj.factory.blank_state(addr=addr)

# _gcry_mpi_invm (gcry_mpi_t x, gcry_mpi_t a, gcry_mpi_t n)
# x = output, calculate inverse_modulo(a,n)
# Values from extracted from tests/prime --42

# gcry_mpi = 3*8 bytes, last 8 bytes = pointer to number
### Define x ###
x_addr = 0x1000
state.mem[x_addr].struct.gcry_mpi.alloced = 0
state.mem[x_addr].struct.gcry_mpi.nlimbs = 0
state.mem[x_addr].struct.gcry_mpi.sign = 0
state.mem[x_addr].struct.gcry_mpi.flags = 0
state.mem[x_addr].struct.gcry_mpi.d = 0

### Define a ###
a_addr = 0x2000
a_d_addr = 0x2100
state.mem[a_addr].struct.gcry_mpi.alloced = 2
state.mem[a_addr].struct.gcry_mpi.nlimbs = 2
state.mem[a_addr].struct.gcry_mpi.sign = 0
state.mem[a_addr].struct.gcry_mpi.flags = 0
state.mem[a_addr].struct.gcry_mpi.d = a_d_addr
secret1 = state.solver.BVS("secret1", 8*8)
secret2 = state.solver.BVS("secret2", 8*8)
setattr(state.mem[a_d_addr] ,'unsigned long', secret1)
setattr(state.mem[a_d_addr+8] ,'unsigned long', secret2)


### Define n ###
n_addr = 0x3000
n_d_addr = 0x3100
state.mem[n_addr].struct.gcry_mpi.alloced = 0x1
state.mem[n_addr].struct.gcry_mpi.nlimbs = 0x1
state.mem[n_addr].struct.gcry_mpi.sign = 0
state.mem[n_addr].struct.gcry_mpi.flags = 0
state.mem[n_addr].struct.gcry_mpi.d = n_d_addr
setattr(state.mem[n_d_addr], 'unsigned long', 0x7)

# state.mem[n_addr].struct.gcry_mpi.alloced = 0x10
# state.mem[n_addr].struct.gcry_mpi.nlimbs = 0x10
# state.mem[n_addr].struct.gcry_mpi.sign = 0
# state.mem[n_addr].struct.gcry_mpi.flags = 0
# state.mem[n_addr].struct.gcry_mpi.d = n_d_addr

# setattr(state.mem[n_d_addr], 'unsigned long', 0x264d749bc2ea0a20)
# setattr(state.mem[n_d_addr+0x08], 'unsigned long', 0xed143b6289b0d7ff)
# setattr(state.mem[n_d_addr+0x10], 'unsigned long', 0xb3db022950779ec5)
# setattr(state.mem[n_d_addr+0x18], 'unsigned long', 0x7aa1c8f0173e658c)
# setattr(state.mem[n_d_addr+0x20], 'unsigned long', 0x41688fb6de052c53)
# setattr(state.mem[n_d_addr+0x28], 'unsigned long', 0x082f567da4cbf31a)
# setattr(state.mem[n_d_addr+0x30], 'unsigned long', 0xcef61d446b92b9e1)
# setattr(state.mem[n_d_addr+0x38], 'unsigned long', 0x15bce40b325980a7)
# setattr(state.mem[n_d_addr+0x40], 'unsigned long', 0x2800d9b28b643d13)
# setattr(state.mem[n_d_addr+0x48], 'unsigned long', 0x613a12ebc49d764f)
# setattr(state.mem[n_d_addr+0x50], 'unsigned long', 0x9a734c24fdd6af88)
# setattr(state.mem[n_d_addr+0x58], 'unsigned long', 0xd3ac855e370fe8c1)
# setattr(state.mem[n_d_addr+0x60], 'unsigned long', 0x0ce5be97704921fa)
# setattr(state.mem[n_d_addr+0x68], 'unsigned long', 0x461ef7d0a9825b34)
# setattr(state.mem[n_d_addr+0x70], 'unsigned long', 0x7f583109e2bb946d)
# setattr(state.mem[n_d_addr+0x78], 'unsigned long', 0x18916a431bf4cda6)

# Prepare state
state.regs.rdi = x_addr
state.regs.rsi = a_addr
state.regs.rdx = n_addr
state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)

traces = [int(x,16) for x in open("traces/libgcrypt/trace2.txt").readlines()]

state.globals["nr_blocks"] = 0
simgr = proj.factory.simgr(state)

callstack_size = len(state.callstack)



def done(state):
    return len(state.callstack) < callstack_size

def impossible(state):
    """Returns False if the current state is impossible by comparing the executed instructions to the trace"""
    i = state.globals["nr_blocks"]
    return state.addr != traces[i]


simgr.found=[]
# while len(simgr.found) < 1 and len(simgr.active) > 0:
for _ in tqdm(traces):
    simgr.move(
        from_stash="active",
        to_stash="found",
        filter_func=done
    )
    simgr.move(from_stash="active", to_stash="avoid", filter_func=impossible)
    for s in simgr.active:
        s.globals["nr_blocks"] += 1

    simgr.step()
  

# Solution
solution = simgr.active[0].solver.eval(secret1)
print("Secret exponent 1 =", hex(solution))
solution = simgr.active[0].solver.eval(secret2)
print("Secret exponent 1 =", hex(solution))
