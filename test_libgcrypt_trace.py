
import angr
import logging

SECRET_EXPONENT = 0xdeadbeefc0ffee
LOG_LEVEL = logging.INFO

logger = logging.getLogger("angr")
logger.setLevel(LOG_LEVEL)
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
state.mem[a_addr].struct.gcry_mpi.alloced = 1
state.mem[a_addr].struct.gcry_mpi.nlimbs = 1
state.mem[a_addr].struct.gcry_mpi.sign = 0
state.mem[a_addr].struct.gcry_mpi.flags = 0
state.mem[a_addr].struct.gcry_mpi.d = a_d_addr
setattr(state.mem[a_d_addr] ,'unsigned long', SECRET_EXPONENT)


### Define n ###
n_addr = 0x3000
n_d_addr = 0x3100
state.mem[n_addr].struct.gcry_mpi.alloced = 0x1
state.mem[n_addr].struct.gcry_mpi.nlimbs = 0x1
state.mem[n_addr].struct.gcry_mpi.sign = 0
state.mem[n_addr].struct.gcry_mpi.flags = 0
state.mem[n_addr].struct.gcry_mpi.d = n_d_addr
setattr(state.mem[n_d_addr], 'unsigned long', 0x7)


# Prepare state
state.regs.rdi = x_addr
state.regs.rsi = a_addr
state.regs.rdx = n_addr
state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
simgr = proj.factory.simgr(state)

simgr.run()
with open("traces/libgcrypt/trace.txt", "w") as f:
  out = "\n".join(hex(x) for x in simgr.errored[0].state.history.bbl_addrs)
  f.write(out)