"""This script traces the square and multiply enclave."""
import logging
import pathlib
import pickle
import os

import spysgx.project
SECRET = 1337

PARENT_PATH = pathlib.Path(__file__).parent
ENCLAVE_PATH = PARENT_PATH / "enclaves" / "square_multiply.signed.so"
PICKLE_PATH = PARENT_PATH / "cache" / "square_multiply.pickle"
TRACEFILE = PARENT_PATH / "traces" / "square_multiply" / "trace.txt"

logging.getLogger("spysgx").setLevel(logging.DEBUG)

# Load the project from a pickle file if it exists
if os.path.exists(PICKLE_PATH):
    with open(PICKLE_PATH, "rb") as f:
        proj = pickle.load(f)
else:
    proj = spysgx.Project(ENCLAVE_PATH, "sgx_mod_exp", PICKLE_PATH)
# Try to reach the mod_exp function
# Set the secret value
proj.guard.simgr.active[0].regs.rsi = SECRET
proj.dump_trace(TRACEFILE)
