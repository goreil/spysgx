""" This script traces the execution of the toy_data_access enclave. """
import logging
import pathlib
import pickle
import os.path

import spysgx

SECRET = 1
PARENT_PATH = pathlib.Path(__file__).parent
ENCLAVE_PATH = PARENT_PATH / "enclaves" / "toy_data_access.signed.so"
PICKLE_PATH = PARENT_PATH / "cache" / "toy_data_access.pickle"
TRACEFILE = PARENT_PATH / "traces" / "toy_data_access" / "trace.txt"

logging.getLogger("spysgx").setLevel(logging.DEBUG)

# Load the project from a pickle file if it exists
if os.path.exists(PICKLE_PATH):
    with open(PICKLE_PATH, "rb") as f:
        proj = pickle.load(f)
else:
    proj = spysgx.Project(ENCLAVE_PATH, "sgx_ecall_access_data", PICKLE_PATH)

# Set the secret value (First parameter)
proj.guard.simgr.active[0].regs.rdi = SECRET
simgr = proj.dump_trace(TRACEFILE, kind="mem")
