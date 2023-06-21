#!/usr/bin/env pypy
""" This script traces the execution of the toy_data_access enclave. """
import logging
import pathlib
import pickle
import os
import random
import click

import angr
import claripy
import spysgx


NAME = "ecb"
PARENT_PATH = pathlib.Path(__file__).parent
# This is not actually an enclave, but a normal ELF file
ENCLAVE_PATH = PARENT_PATH / "enclaves" / f"{NAME}"
PICKLE_PATH = PARENT_PATH / "cache" / f"{NAME}.pickle"

@click.command()
@click.option("--secret", default=1337, help="The secret value to trace.")
@click.option("--tracefolder", default= PARENT_PATH / "traces" / f"{NAME}", help="The trace folder to write to.")
@click.option("--num", default=1, help="The number of traces to generate. If this number is > 1 then the secret will be generated randomly.")
@click.option("--debug", is_flag=True, help="Enable debug mode.")
def argparse(secret, tracefolder, num, debug):
    """Parse the command line arguments."""
    if debug:
        logging.getLogger("angr").setLevel(logging.DEBUG)
    else:
        logging.getLogger("angr").setLevel(logging.WARN)

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
        state = proj.factory.entry_state(
            args=["./ecb", secret],
            add_options= {angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
#                 angr.options.TRACK_MEMORY_ACTIONS,
                angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS}
        
        )
        simgr = proj.factory.simgr(state)
        spysgx.trace(simgr, tracefile, kind="mem")


if __name__ == "__main__":
    if os.path.exists(PICKLE_PATH):
        with open(PICKLE_PATH, "rb") as f:
            proj = pickle.load(f)
    else:
        proj = angr.Project(ENCLAVE_PATH)
        with open(PICKLE_PATH, "wb") as f:
            pickle.dump(proj, f)

    argparse()
