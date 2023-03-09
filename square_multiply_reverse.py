import spysgx.project
import claripy
import logging
import pathlib

PARENT_PATH = pathlib.Path(__file__).parent
ENCLAVE_PATH = PARENT_PATH / "enclaves" / "square_multiply.signed.so"
TRACEFILE = PARENT_PATH/ "traces" / "square_multiply" / "trace.txt"

logging.getLogger("spysgx").setLevel(logging.DEBUG)

proj = spysgx.project.Project(ENCLAVE_PATH)
# Try to reach the mod_exp function
proj.reach_symbol("mod_exp")

# Reversing
secret = claripy.BVS("secret", 64)
proj.guard.simgr.active[0].regs.rsi = secret
simgr = proj.reverse_trace(TRACEFILE)
print("Secret =", simgr.found[0].solver.eval(secret, cast_to=int))