#ifndef PSA_CRYPTO_DRIVER_WRAPPER_H
#define PSA_CRYPTO_DRIVER_WRAPPER_H 

#include <stdlib.h>
#include "kernel_defines.h"
#include "psa/psa_crypto_values.h"
#include "psa/psa_crypto_types.h"

#if IS_ACTIVE(CONFIG_MODULE_PERIPH_CC_HW_HASHES)
#include "cc_hw_hashes.h"
#endif

#if IS_ACTIVE(CONFIG_MODULE_CRYPTOAUTHLIB_HASHES)
#include "atca_hw_hashes.h"
#endif

typedef union
{
    unsigned dummy; /* Make the union non-empty even with no supported algorithms. */

    #if IS_ACTIVE(CONFIG_MODULE_PERIPH_CC_HW_HASHES)
        cc_hash_hwctx_t cc_ctx;
    #endif
    #if IS_ACTIVE(CONFIG_MODULE_CRYPTOAUTHLIB_HASHES_SHA256)
        atca_hash_ctx_t atca_sha256;
    #endif
} psa_hash_hw_context_t;

psa_status_t psa_driver_wrapper_hash_setup(psa_hash_operation_t * operation,
                                           psa_algorithm_t alg);

psa_status_t psa_driver_wrapper_hash_update(psa_hash_operation_t * operation,
                             const uint8_t * input,
                             size_t input_length);

psa_status_t psa_driver_wrapper_hash_finish(psa_hash_operation_t * operation,
                             uint8_t * hash);

#endif
