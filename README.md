# SpySGX: Automatic Reversing of Secrets from Memory Traces in SGX-Enclaves
![2023-08-07_SpySGX_Poster-1](https://github.com/goreil/spysgx/assets/90871590/d7683850-4ffe-4177-90d8-cf3e104add50)

## Guided symbolic Execution animated
<img src="https://github.com/goreil/spysgx/assets/90871590/946aaee5-ac2c-489e-bc68-503675181f36"/>



## What can this do?
1. It's an Emulator that helps **collect memory accesses** on Intel SGX-Enclaves:
Give it a Intel-SGX enclave, select a function and you can trace the memory accesses. 
2. It's a automated attacker: Given a memory access trace (created by 1.), it attempts to reverse a select function parameter using symbolic execution.



## Abstract
Intel Software Guard Extensions (SGX) enable the creation of enclaves 
for secure deployment of sensitive data in cloud computing. However, memory-based side-channel attacks pose a threat to SGX enclaves, compromising their confidentiality. Although enclave library developers are responsible for addressing side-channel attacks, writing side-channel free code is challenging.

We identified a research gap in the verification step, assessing whether a potential side-channel vulnerability is strong enough to leak the secret. To address
this, we propose SpySGX, a framework combining symbolic execution and data
analysis to automatically leak secrets from enclave Libraries. Unlike existing approaches, SpySGX does not require a specific type of memory-access patterns and
can be applied to a broader set of enclave Libraries. Additionally, we explore the
effectiveness of limiting memory-accesses to mitigate side-channel attacks. We develop two approaches to handle incomplete memory traces and demonstrate their
efficacy through testing on two enclave Libraries.

Our results show that SpySGX consistently leaks the complete secret given the
full trace, verifying the existence of a side-channel vulnerability. Furthermore, our
missing instruction heuristic successfully recovers the complete secret in 98 % of
cases with 25 % trace incompleteness. For data-access traces, our dynamic timewarping approach demonstrates near-perfect imputation. These findings emphasize the insufficiency of limiting memory-accesses in preventing memory-based
side-channel attacks






## Thesis
* Written Thesis: [Thesis.pdf](Thesis.pdf)
* Presentation: [SpySGX.pptx](SpySGX_Presentation.pptx)

## Requirements and Notes
* angr=9.2.29 
* guardian https://github.com/blockhousetech/guardian
* At time of writing guardian only supports enclaves that are build with Intel SDK version 2.12


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

