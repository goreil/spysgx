# spysgx
Memory tracing and reversing of SGX-Enclaves

## Requirements
angr=9.2.29 
guardian (https://github.com/blockhousetech/guardian)


## Basic examples:
* Instruction tracing: `python3 square_multiply_trace.py [SECRET]`
* Instruction reversing: `python3 square_multiply_reverse.py`
* Data access tracing: `python3 sub_bytes_trace.py [SECRET]`
* Data access reversing: `python3 sub_bytes_trace.py`

## Repository structure
* `enclaves` contains the target enclaves with their source
* `spysgx` contains the `spysgx` framework for tracing and reversing enclaves
* `traces` contains the generated traces from the examples
* `cache` is a folder for `.pickle` file to speed up analysis in the second run

