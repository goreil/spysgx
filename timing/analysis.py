from trace_sqr_mlt import trace
from rev_sqr_mlt import symbolic_reverse_with_trace
import time
import random
import os

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
if not os.path.isfile("spysgx_discret_log.csv"):

    for l in data:
        bits,gen,prime,real_exponent,target,elapsed = [int(x) for x in l.split(",")]
        if bits == last_bits:
            continue

        trace(gen, prime, real_exponent, tracefile = "trace.txt")
        start = time.time()
        calculated_exponent = symbolic_reverse_with_trace(gen, prime, target, tracefile = "trace.txt")
        elapsed = time.time() - start
        assert calculated_exponent == real_exponent
        print(f"Bits = {bits} Time taken {elapsed:0.2f} seconds:")
        last_bits = bits
        with open("spysgx_discret_log.csv", "a") as f:
            f.write(",".join([str(int(ele)) for ele in [bits, gen, prime, real_exponent, target, elapsed * 1000000]]))
            f.write("\n")
    
# Additional data up to 2^63
data = """16302590302128227 2 550486813686712
23249874762058727 5 3117129946070912
49421361382468499 2 41423824076027573
120274477475780939 2 23220945270839555
168425296341539219 2 17367661667555293
572777026054659467 2 255475014268077803
1144044817212404447 5 478010786109271905
1568548029376699643 2 668403809780870475
2519781686813574419 2 2055413071095879927
7185861075956929259 2 6776522725579256991 """

for l in data.split("\n"):
    prime,gen,real_exponent = [int(x) for x in l.split()]
    bits = len(bin(prime)) - 2

    target = trace(gen, prime, real_exponent, tracefile = "trace.txt")
    start = time.time()
    calculated_exponent = symbolic_reverse_with_trace(gen, prime, target, tracefile = "trace.txt")
    elapsed = time.time() - start
    assert calculated_exponent == real_exponent
    print(f"Bits = {bits} Time taken {elapsed:0.2f} seconds:")
    last_bits = bits
    with open("spysgx_discret_log.csv", "a") as f:
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
