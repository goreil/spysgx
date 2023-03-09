import spysgx.project
import claripy
import logging
import pathlib

SECRET = 1337

PARENT_PATH = pathlib.Path(__file__).parent
ENCLAVE_PATH = PARENT_PATH / "enclaves" / "square_multiply.signed.so"
TRACEFILE = PARENT_PATH / "traces" / "square_multiply" / "trace.txt"

logging.getLogger("spysgx").setLevel(logging.DEBUG)

proj = spysgx.project.Project(ENCLAVE_PATH)
# Try to reach the mod_exp function
proj.reach_symbol("mod_exp")
# Set the secret value
proj.guard.simgr.active[0].regs.rsi = SECRET
proj.dump_trace(TRACEFILE)
