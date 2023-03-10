""" This script traces the execution of the sgx_gmp_2.6.signed.so enclave. """
import logging
import pathlib
import pickle
import os.path

import spysgx.project

SECRET = 10
PARENT_PATH = pathlib.Path(__file__).parent
ENCLAVE_PATH = PARENT_PATH / "enclaves" / "sgx_gmp_2.6.signed.so"
TRACEFILE = PARENT_PATH/ "traces" / "sgx_gmp" / "trace.txt"
PICKLE_PATH = PARENT_PATH / "cache" / "sgx_gmp.pickle"

logging.getLogger("spysgx").setLevel(logging.DEBUG)

if os.path.exists(PICKLE_PATH):
    with open(PICKLE_PATH, "rb") as f:
        proj = pickle.load(f)
else:
    proj = spysgx.Project(ENCLAVE_PATH, "sgx_e_pi", PICKLE_PATH)
# Set the secret value (First parameter)
proj.guard.simgr.active[0].regs.rdi = SECRET
proj.dump_trace(TRACEFILE)
