#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <stdint.h>

typedef __int128 int128_t;

uint64_t square_mult(uint64_t base_64, uint64_t exponent, uint64_t prime_64) {
    int128_t result = 1;
    int128_t base = base_64;
    int128_t prime = prime_64;
    while (exponent > 0) {
        if (exponent % 2 == 1)
            result = (result * base) % prime;
        exponent = exponent >> 1;
        base = (base * base) % prime;
    }
    
    return (uint64_t) (result & 0xFFFFFFFFFFFFFFFFULL);
}

uint64_t base = 3ULL; // primitive root of prime
uint64_t prime = 8555135299883116411ULL; // 63-bit prime

int main(int argc, char** argv) {
    int64_t exponent;
    // printf("prime: %lu\n", prime);
    if (argc > 1) {
        exponent = strtoull(argv[1], NULL, 10);
    } else {
        puts("Usage: square_multiply <exponent>");
        return 1;
    }
    uint64_t result = square_mult(base, exponent, prime);
    // split result into two 64-bit integers
    printf("0x%lx\n", result);

    return 0;
}