#include <stdio.h>

#include "kernel_defines.h"

#if IS_ACTIVE(CONFIG_HW_HASHES_ENABLED)
#include "psa/crypto.h"

#if IS_ACTIVE(CONFIG_MODULE_PERIPH_CC_HW_HASHES)
#include "cc_hw_hashes.h"
#endif

#if IS_ACTIVE(CONFIG_MODULE_CRYPTOAUTHLIB_HASHES)
#include "atca_hw_hashes.h"
#endif


psa_status_t psa_driver_wrapper_hash_setup(psa_hash_operation_t * operation,
                                           psa_algorithm_t alg)
{
    psa_status_t status = PSA_ERROR_NOT_SUPPORTED;

    #if IS_ACTIVE(CONFIG_MODULE_PERIPH_CC_HW_HASHES)
        status = cc_hash_setup(operation, alg);
    #endif

    #if IS_ACTIVE(CONFIG_MODULE_CRYPTOAUTHLIB_HASHES_SHA256)
    if (status == PSA_ERROR_NOT_SUPPORTED) {
        status = atca_hash_setup(operation, alg);
    }
    #endif

    return status;
}

psa_status_t psa_driver_wrapper_hash_update(psa_hash_operation_t * operation,
                             const uint8_t * input,
                             size_t input_length)
{
    psa_status_t status = PSA_ERROR_NOT_SUPPORTED;

    #if IS_ACTIVE(CONFIG_MODULE_PERIPH_CC_HW_HASHES)
        status = cc_hash_update(operation, input, input_length);
    #endif

    #if IS_ACTIVE(CONFIG_MODULE_CRYPTOAUTHLIB_HASHES_SHA256)
    if (status == PSA_ERROR_NOT_SUPPORTED) {
        status = atca_hash_update(operation, input, input_length);
    }
    #endif
    
    return status;
}

psa_status_t psa_driver_wrapper_hash_finish(psa_hash_operation_t * operation,
                             uint8_t * hash)
{
    psa_status_t status = PSA_ERROR_NOT_SUPPORTED;

    #if IS_ACTIVE(CONFIG_MODULE_PERIPH_CC_HW_HASHES)
        status = cc_hash_finish(operation, hash);
    #endif

    #if IS_ACTIVE(CONFIG_MODULE_CRYPTOAUTHLIB_HASHES_SHA256)
    if (status == PSA_ERROR_NOT_SUPPORTED) {
        status = atca_hash_finish(operation, hash);
    }
    #endif

    return status;
}
#endif /* CONFIG_HW_HASHES_ENABLED */