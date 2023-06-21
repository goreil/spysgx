#include <gmp.h>

void square_mult(mpz_t result, mpz_t base, mpz_t exponent, mpz_t prime) {
    mpz_t base_mod;
    mpz_init(base_mod);
    mpz_mod(base_mod, base, prime);

    mpz_set_ui(result, 1);

    for (mpz_t i; mpz_cmp_ui(exponent, 0) > 0; mpz_fdiv_q_2exp(exponent, exponent, 1)) {
        if (mpz_odd_p(exponent)) {
            mpz_mul(result, result, base_mod);
            mpz_mod(result, result, prime);
        }
        mpz_mul(base_mod, base_mod, base_mod);
        mpz_mod(base_mod, base_mod, prime);
    }

    mpz_clear(base_mod);
}

int main(){
    
}