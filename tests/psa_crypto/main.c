#include <stdio.h>
#include <stdint.h>
// #include "psa/crypto.h"

int32_t val_entry(void);

int main(void)
{
    // if (psa_crypto_init() == PSA_SUCCESS) {
    //     puts("PSA Init successful");
    // }

    // psa_hash_operation_t sha1 = psa_hash_operation_init();
    // psa_hash_operation_t sha256 = psa_hash_operation_init();

    // int status = psa_hash_setup(&sha1, PSA_ALG_SHA_1);
    // if (status != PSA_SUCCESS) {
    //     printf("SHA1 Setup failed: %d\n", status);
    // }

    // status = psa_hash_setup(&sha256, PSA_ALG_SHA_256);
    // if (status != PSA_SUCCESS) {
    //     printf("SHA256 Setup failed: %d\n", status);
    // }
    // return 1;
    printf("Starting Main.c\n");
    return val_entry();
}