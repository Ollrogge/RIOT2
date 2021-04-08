#include <stdio.h>
#include "kernel_defines.h"
#include "psa/crypto.h"
#include "hw_hashes.h"

#include "cryptocell_util.h"
#include "cryptocell_incl/crys_hash.h"
#include "cryptocell_incl/crys_hash_error.h"

psa_status_t psa_driver_wrapper_hash_setup(psa_hash_operation_t * operation,
                                           psa_algorithm_t alg)
{
    return cc_hash_setup(operation, alg);
}

psa_status_t psa_driver_wrapper_hash_update(psa_hash_operation_t * operation,
                             const uint8_t * input,
                             size_t input_length)
{
    return cc_hash_update(operation, input, input_length);
}

psa_status_t psa_driver_wrapper_hash_finish(psa_hash_operation_t * operation,
                             uint8_t * hash)
{
    return cc_hash_finish(operation, hash);
}