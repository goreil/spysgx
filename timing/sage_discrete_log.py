from sage.all import *
import time

# get a prime p such that p-1 has a large prime factor
def get_prime(bits):
    while True:
        p = random_prime(2**(bits-1), lbound=2**(bits-2))
        if is_prime(2*p + 1):
            return 2*p + 1


for i in range(4, 100):
    elapsed = 0
    count = 0
    while (elapsed < 2 and count < 1000):
        p = get_prime(i)
        F = GF(p)
        g = F.multiplicative_generator()

        # get a random exponent
        x = randint(1, p-2)
        # Calculate discrete log
        start = time.time()
        y = discrete_log(g**x, g)
        current_elapsed = time.time() - start
        elapsed += current_elapsed
        assert x == y
        with open("sage_discrete_log.csv", "a") as f:
            f.write(",".join([str(int(ele)) for ele in [i, g, p, x, g**x, current_elapsed * 1000000]]))
            f.write("\n")

        count += 1
    print(f"Calculations = {count} Bits = {i} Time taken {elapsed:0.2f} seconds:")
    

