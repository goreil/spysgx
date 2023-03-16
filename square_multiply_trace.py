"""This script traces the square and multiply enclave."""
import logging
import pathlib
import pickle
import os
import sys
import random
import click

import spysgx.project

PARENT_PATH = pathlib.Path(__file__).parent

ENCLAVE_PATH = PARENT_PATH / "enclaves" / "square_multiply.signed.so"
PICKLE_PATH = PARENT_PATH / "cache" / "square_multiply.pickle"

@click.command()
@click.option("--secret", default=1337, help="The secret value to trace.")
@click.option("--tracefolder", default=PARENT_PATH / "traces" / "square_multiply", help="The trace folder to write to.")
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
        secrets = [random.randint(0, 2**30) for _ in range(num)]
    else:
        secrets = [secret]

    for i, secret in enumerate(secrets, 1):
        print(f"Tracing secret {i}/{num}")
        tracefile = tracefolder / f"trace_{secret}.txt"
        proj.guard.simgr.active[0].regs.rsi = secret
        spysgx.trace(proj.guard.simgr, tracefile)

# Load the project from a pickle file if it exists
if __name__ == "__main__":
    if os.path.exists(PICKLE_PATH):
        with open(PICKLE_PATH, "rb") as f:
            proj = pickle.load(f)
    else:
        proj = spysgx.Project(ENCLAVE_PATH, "sgx_mod_exp", PICKLE_PATH)
    # Try to reach the mod_exp function
    
    # Start tracing
    argparse()

