import pathlib
import pandas as pd
import numpy as np


FOLDER_PATH = pathlib.Path(".") / "sub_bytes_2"
OUTPUT_PATH = pathlib.Path(".") / "sub_bytes_2.csv"

try: 
    # Try to load the CSV File
    df = pd.read_csv(OUTPUT_PATH)
    print("CSV already exists")
except FileNotFoundError:
    # Get all trace files in FOLDER_PATH
    trace_files = list(FOLDER_PATH.glob("*.txt"))

    # Create a dataframe with the trace files

    # Create a list of lists
    # Each list is a row in the dataframe
    # The first column is the secret value (analysed from the filename)
    # The rest of the colums are the instruction addresse

    data = []
    max_len = 0
    for trace_file in trace_files:
        # Get the secret value from the filename

        secret = int(trace_file.stem.split("_")[1])
        # Read the trace file
        with open(trace_file, "r") as f:
            trace = [int(x, 16) for x in f.read().splitlines()]
        # Add the secret value and the trace to the list of lists
        max_len = max(max_len, len(trace))
        data.append([trace_file.name, secret] + trace)

    # Create the dataframe
    df = pd.DataFrame(data, columns=["trace_file", "secret"] + [f"mem{i}" for i in range(max_len)])

    df.to_csv(OUTPUT_PATH, index = False)
