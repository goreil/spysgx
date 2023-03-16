"""This script reverses the square multiply enclave to find the secret value."""
import logging
import pathlib
import os
import pickle
import claripy
import click

import spysgx
PARENT_PATH = pathlib.Path(__file__).parent
ENCLAVE_PATH = PARENT_PATH / "enclaves" / "square_multiply.signed.so"
PICKLE_PATH = PARENT_PATH / "cache" / "square_multiply.pickle"

@click.command()
@click.option("--tracefolder", default=PARENT_PATH / "traces" / "square_multiply", help="The trace folder that contains the secrets.")
@click.option("--results", default=None, help="The file to write the results to. If none is given then the results will not be printed.")
@click.option("--debug", is_flag=True, help="Enable debug mode.")
def argparse(tracefolder, results, debug):
    """Parse the command line arguments."""
    if debug:
        logging.getLogger("spysgx").setLevel(logging.DEBUG)
    else:
        logging.getLogger("spysgx").setLevel(logging.INFO)
    tracefolder = pathlib.Path(tracefolder)

    # Get all the trace files form the trace folder
    tracefiles = [tracefile for tracefile in tracefolder.iterdir() if tracefile.is_file()]
    print(tracefiles)

    for i, tracefile in enumerate(tracefiles, 1):
        print(f"Tracing secret {i}/{len(tracefiles)}")
        if os.path.exists(PICKLE_PATH):
            with open(PICKLE_PATH, "rb") as f:
                proj = pickle.load(f)
        else:
            proj = spysgx.Project(ENCLAVE_PATH, "sgx_mod_exp", PICKLE_PATH)

        # Set the secret value to a symbolic variable
        secret = claripy.BVS("secret", 64)
        proj.guard.simgr.active[0].regs.rsi = secret
        state = spysgx.reverse(proj.guard.simgr, tracefile)
        secret = state.solver.eval(secret, cast_to=int)

        if results is not None:
            with open(results, "a+") as f:
                f.write(f"{tracefile.name}, {secret}\n")
        
        print(f"{tracefile.name}, {secret}")
        # import IPython; IPython.embed()

# Start reversing
if __name__ == "__main__":
    argparse()
