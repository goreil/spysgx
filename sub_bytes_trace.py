""" This script traces the execution of the toy_data_access enclave. """
import logging
import pathlib
import pickle
import os.path

import claripy
import spysgx

SECRET = claripy.BVV(0x0001020304050607, 64)
NAME = "sub_bytes"
PARENT_PATH = pathlib.Path(__file__).parent
ENCLAVE_PATH = PARENT_PATH / "enclaves" / f"{NAME}.signed.so"
PICKLE_PATH = PARENT_PATH / "cache" / f"{NAME}.pickle"
TRACEFILE = PARENT_PATH / "traces" / f"{NAME}" / "trace.txt"

logging.getLogger("spysgx").setLevel(logging.DEBUG)

# Load the project from a pickle file if it exists
if os.path.exists(PICKLE_PATH):
    with open(PICKLE_PATH, "rb") as f:
        proj = pickle.load(f)
else:
    proj = spysgx.Project(ENCLAVE_PATH, "sgx_ecall_SubBytes", PICKLE_PATH)

# Set the secret value (First parameter)
proj.guard.simgr.active[0].regs.rdi = SECRET
spysgx.trace(proj.guard.simgr, TRACEFILE, kind="mem")
