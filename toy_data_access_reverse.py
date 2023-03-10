""" This script traces the execution of the toy_data_access enclave. """
import logging
import pathlib
import claripy
import spysgx.project

SECRET = claripy.BVS("secret", 64)
PARENT_PATH = pathlib.Path(__file__).parent
ENCLAVE_PATH = PARENT_PATH / "enclaves" / "toy_data_access.signed.so"
TRACEFILE = PARENT_PATH/ "traces" / "toy_data_access" / "trace.txt"

logging.getLogger("spysgx").setLevel(logging.DEBUG)

proj = spysgx.project.Project(ENCLAVE_PATH, "sgx_ecall_access_data")
# Try to reach the ecall_access_data function
proj.reach_symbol("ecall_access_data")
# Set the secret value (First parameter)

proj.guard.simgr.active[0].regs.rdi = SECRET
simgr = proj.dump_trace(TRACEFILE, kind="mem")
state = simgr.found[0]
