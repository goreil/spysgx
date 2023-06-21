""" This script traces the execution of the toy_data_access enclave. """
import logging
import pathlib
import os
import pickle
import claripy
import click

import spysgx.project

SECRET = claripy.BVS("secret", 64)
NAME = "sub_bytes"
PARENT_PATH = pathlib.Path(__file__).parent
ENCLAVE_PATH = PARENT_PATH / "enclaves" / f"{NAME}.signed.so"
PICKLE_PATH = PARENT_PATH / "cache" / f"{NAME}.pickle"
#TRACEFILE = PARENT_PATH / "traces" / f"{NAME}" / "trace.txt"
TRACEFILE = PARENT_PATH/ "traces"/"sub_bytes"/ "trace_10054330088175825702.txt"

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

@click.command()
@click.option("--tracefolder", default=PARENT_PATH / "traces" / "sub_bytes", help="The trace folder that contains the secrets.")
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
        print(f"Reversing trace {i}/{len(tracefiles)}")
        # Load the pickle file if it exists (Has to be done for every tracefile again)
        if os.path.exists(PICKLE_PATH):
            with open(PICKLE_PATH, "rb") as f:
                proj = pickle.load(f)
        else:
            proj = spysgx.Project(ENCLAVE_PATH, "sgx_ecall_access_data", PICKLE_PATH)

        # Set the secret value to a symbolic variable
        secret = claripy.BVS("secret", 64)
        proj.guard.simgr.active[0].regs.rsi = secret
        state = spysgx.reverse(proj.guard.simgr, tracefile, kind="mem")
        secret = state.solver.eval(secret, cast_to=int)

        if results is not None:
            with open(results, "a+") as f:
                f.write(f"{tracefile.name}, {secret}\n")

        print(f"{tracefile.name}, {secret}")
        # import IPython; IPython.embed()

# Start reversing
if __name__ == "__main__":
    argparse()
