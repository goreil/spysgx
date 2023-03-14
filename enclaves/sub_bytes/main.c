#include <stdio.h>
#include <string.h>

#include <stdbool.h>
#include "sgx_urts.h"
#include "enclave_u.h"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;


/* OCall functions */


int main(int argc, char *argv[]) {
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
    int updated = 0;
    // Create enclave
    if(sgx_create_enclave("enclave.signed.so", SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL) != SGX_SUCCESS) {
        printf("Failed to start enclave!\n");
        return -1;
    }

    // Call into enclave
    
    uint64_t secret = 0x0001020304050607;
    uint64_t retval;
    ecall_SubBytes(global_eid, &retval, secret);
    // Destroy enclave
    sgx_destroy_enclave(global_eid);
    
    printf("Enclave returned\n");
    printf("OUT = %8lx", retval);

    return 0;
}

