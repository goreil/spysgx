from trace_sqr_mlt import trace
from rev_sqr_mlt import symbolic_reverse_with_trace
import time
import random

output = []
def bruteforce(base, prime, target):
    exponent = 0
    while True:
        if pow(base, exponent, prime) == target:
            return exponent
        exponent += 1

with open("sage_discrete_log.csv", "r") as f:
    data = f.readlines()

last_bits = 0   
for l in data:
    bits,gen,prime,real_exponent,target,elapsed = [int(x) for x in l.split(",")]
    if bits == last_bits:
        continue

    trace(gen, prime, real_exponent, tracefile = "trace.txt")
    start = time.time()
    calculated_exponent = symbolic_reverse_with_trace(gen, prime, target, tracefile = None, bound = 2**bits + 1)
    elapsed = time.time() - start
    assert calculated_exponent == real_exponent
    print(f"Bits = {bits} Time taken {elapsed:0.2f} seconds:")
    last_bits = bits
    with open("spysgx_no_trace_discret_log.csv", "a") as f:
        f.write(",".join([str(int(ele)) for ele in [bits, gen, prime, real_exponent, target, elapsed * 1000000]]))
        f.write("\n")


    




# for i in range(2, 63):
#     real_exponent = random.randint(0, 2**i)
#     target = trace(real_exponent)
#     start = time.time()
    
#     result = None
#     while (result is None):
#         result = bruteforce(target, bound = (2**i) + 1)
    
#     calculated_exponent = result
#     print(real_exponent, calculated_exponent)
#     end = time.time()
#     assert calculated_exponent == real_exponent
#     print(f"Bits = {i} Time taken {end-start:0.2f} seconds:")
