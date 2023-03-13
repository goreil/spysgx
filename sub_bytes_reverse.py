""" This script traces the execution of the toy_data_access enclave. """
import logging
import pathlib
import os
import pickle
import claripy

import spysgx.project

SECRET = claripy.BVS("secret", 64)
NAME = "sub_bytes"
PARENT_PATH = pathlib.Path(__file__).parent
ENCLAVE_PATH = PARENT_PATH / "enclaves" / f"{NAME}.signed.so"
PICKLE_PATH = PARENT_PATH / "cache" / f"{NAME}.pickle"
TRACEFILE = PARENT_PATH / "traces" / f"{NAME}" / "trace.txt"

logging.getLogger("spysgx").setLevel(logging.DEBUG)

if os.path.exists(PICKLE_PATH):
    with open(PICKLE_PATH, "rb") as f:
        proj = pickle.load(f)
else:
    proj = spysgx.Project(ENCLAVE_PATH, "sgx_ecall_access_data", PICKLE_PATH)
# Set the secret value (First parameter)

proj.guard.simgr.active[0].regs.rdi = SECRET
# Reverse the trace
state = spysgx.reverse(proj.guard.simgr, TRACEFILE, kind="mem")
# Print the secret value
print("SECRET = " + hex(state.solver.eval(SECRET)))
