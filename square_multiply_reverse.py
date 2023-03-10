"""This script reverses the square multiply enclave to find the secret value."""
import logging
import pathlib
import os
import pickle
import claripy

import spysgx.project

PARENT_PATH = pathlib.Path(__file__).parent
ENCLAVE_PATH = PARENT_PATH / "enclaves" / "square_multiply.signed.so"
TRACEFILE = PARENT_PATH / "traces" / "square_multiply" / "trace.txt"
PICKLE_PATH = PARENT_PATH / "cache" / "square_multiply.pickle"

logging.getLogger("spysgx").setLevel(logging.DEBUG)

if os.path.exists(PICKLE_PATH):
    with open(PICKLE_PATH, "rb") as f:
        proj = pickle.load(f)
else:
    proj = spysgx.project.Project(ENCLAVE_PATH, "sgx_mod_exp", PICKLE_PATH)

# Reversing
secret = claripy.BVS("secret", 64)
proj.guard.simgr.active[0].regs.rsi = secret
simgr = proj.reverse_trace(TRACEFILE)
print("Secret =", simgr.found[0].solver.eval(secret, cast_to=int))