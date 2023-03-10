""" This script traces the execution of the sgx_gmp_2.6.signed.so enclave. """
import spysgx.project
import logging
import pathlib

SECRET = 10
PARENT_PATH = pathlib.Path(__file__).parent
ENCLAVE_PATH = PARENT_PATH / "enclaves" / "sgx_gmp_2.6.signed.so"
TRACEFILE = PARENT_PATH/ "traces" / "sgx_gmp" / "trace.txt"

logging.getLogger("spysgx").setLevel(logging.DEBUG)

proj = spysgx.project.Project(ENCLAVE_PATH, "sgx_e_pi")
# Try to reach the mod_exp function
proj.reach_symbol("e_pi")
# Set the secret value (First parameter)
proj.guard.simgr.active[0].regs.rdi = SECRET
proj.dump_trace(TRACEFILE)
