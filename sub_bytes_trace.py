""" This script traces the execution of the toy_data_access enclave. """
import logging
import pathlib
import pickle
import os
import random
import click

import claripy
import spysgx


NAME = "sub_bytes"
PARENT_PATH = pathlib.Path(__file__).parent
ENCLAVE_PATH = PARENT_PATH / "enclaves" / f"{NAME}.signed.so"
PICKLE_PATH = PARENT_PATH / "cache" / f"{NAME}.pickle"

@click.command()
@click.option("--secret", default=1337, help="The secret value to trace.")
@click.option("--tracefolder", default= PARENT_PATH / "traces" / "sub_bytes", help="The trace folder to write to.")
@click.option("--num", default=1, help="The number of traces to generate. If this number is > 1 then the secret will be generated randomly.")
@click.option("--debug", is_flag=True, help="Enable debug mode.")
def argparse(secret, tracefolder, num, debug):
    """Parse the command line arguments."""
    if debug:
        logging.getLogger("spysgx").setLevel(logging.DEBUG)
    else:
        logging.getLogger("spysgx").setLevel(logging.INFO)

    tracefolder = pathlib.Path(tracefolder)
    tracefolder.mkdir(parents=True, exist_ok=True)

    if num > 1:
        secrets = [random.randint(0, 2**64) for _ in range(num)]
    else:
        secrets = [secret]

    for i, secret in enumerate(secrets, 1):
        print(f"Tracing secret {i}/{num}")
        tracefile = tracefolder / f"trace_{secret}.txt"
        secret = claripy.BVV(secret, 64)
        proj.guard.simgr.active[0].regs.rdi = secret
        spysgx.trace(proj.guard.simgr, tracefile, kind="mem")


if __name__ == "__main__":
    if os.path.exists(PICKLE_PATH):
        with open(PICKLE_PATH, "rb") as f:
            proj = pickle.load(f)
    else:
        proj = spysgx.Project(ENCLAVE_PATH, "sgx_ecall_access_data", PICKLE_PATH)
    # Try to reach the mod_exp function
    
    # Start tracing
    argparse()
