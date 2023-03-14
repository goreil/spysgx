#include <stdarg.h>
#include "enclave_t.h"

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

uint64_t __attribute__((aligned(4096))) square(uint64_t x) {
    return x * x;
}

uint64_t __attribute__((aligned(4096))) multiply(uint64_t x, uint64_t y) {
    return x * y;
}

uint64_t __attribute__((aligned(4096))) mod_exp(uint64_t base, uint32_t exp, uint64_t mod) {
    int bits = sizeof(exp) * 8;
    uint64_t result = 1;
    for(int i = bits - 1; i >= 0; i--) {
        result = square(result);
        if(exp & (1ull << i)) {
            result = multiply(result, base);
        }
        result = result % mod;
    }
    return result;
}