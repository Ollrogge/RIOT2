/*
 * Copyright (C) 2021 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     sys_psa_crypto
 * @{
 *
 * @file
 * @brief       Wrapper to combine several available cryptographic backends.
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#include "kernel_defines.h"
#include "psa/crypto.h"
#include "psa/builtin_hashes.h"

#if IS_ACTIVE(CONFIG_PERIPH_HASHES)
#include "periph_hashes.h"
#endif
#if IS_ACTIVE(CONFIG_MODULE_CRYPTOAUTHLIB_HASHES)
#include "atca_hashes.h"
#endif

#define PSA_CRYPTO_BUILTIN_DRIVER_ID    (1)
#if IS_ACTIVE(CONFIG_PERIPH_HASHES)
#define PSA_CRYPTO_PERIPH_DRIVER_ID     (2)
#endif
#if IS_ACTIVE(CONFIG_SE_HASHES)
#define PSA_CRYPTO_SE_DRIVER_ID         (3)
#endif

psa_status_t psa_driver_wrapper_hash_setup(psa_hash_operation_t * operation,
                                           psa_algorithm_t alg)
{
    psa_status_t status = PSA_ERROR_NOT_SUPPORTED;

    #if IS_ACTIVE(CONFIG_PERIPH_HASHES)
    status = periph_hash_setup(&(operation->ctx.periph_ctx), alg);
    if (status == PSA_SUCCESS) {
        operation->driver_id = PSA_CRYPTO_PERIPH_DRIVER_ID;
    }
    if (status != PSA_ERROR_NOT_SUPPORTED) {
        return status;
    }
    #endif

    #if IS_ACTIVE(CONFIG_MODULE_HASHES)
    status = psa_builtin_hash_setup(operation, alg);
    if (status == PSA_SUCCESS) {
        operation->driver_id = PSA_CRYPTO_BUILTIN_DRIVER_ID;
    }
    if (status != PSA_ERROR_NOT_SUPPORTED) {
        return status;
    }
    #endif

    #if IS_ACTIVE(CONFIG_MODULE_CRYPTOAUTHLIB_HASHES)
    status = atca_hash_setup(&(operation->ctx.atca_ctx), alg);
    if (status == PSA_SUCCESS) {
        operation->driver_id = PSA_CRYPTO_SE_DRIVER_ID;
    }
    if (status != PSA_ERROR_NOT_SUPPORTED) {
        return status;
    }
    #endif
    (void) status;
    (void) operation;
    (void) alg;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_driver_wrapper_hash_update(psa_hash_operation_t * operation,
                             const uint8_t * input,
                             size_t input_length)
{
    switch(operation->driver_id) {
    #if IS_ACTIVE(CONFIG_PERIPH_HASHES)
        case PSA_CRYPTO_PERIPH_DRIVER_ID:
            return periph_hash_update(&(operation->ctx.periph_ctx), input, input_length);
    #endif

    #if IS_ACTIVE(CONFIG_MODULE_HASHES)
        case PSA_CRYPTO_BUILTIN_DRIVER_ID:
            return psa_builtin_hash_update(operation, input, input_length);
    #endif

    #if IS_ACTIVE(CONFIG_MODULE_CRYPTOAUTHLIB_HASHES)
        case PSA_CRYPTO_SE_DRIVER_ID:
            return atca_hash_update(&(operation->ctx.atca_ctx), input, input_length);
    #endif
        default:
            (void) input;
            (void) input_length;
            return PSA_ERROR_BAD_STATE;
    }
}

psa_status_t psa_driver_wrapper_hash_finish(psa_hash_operation_t * operation,
                             uint8_t * hash,
                             size_t hash_size,
                             size_t * hash_length)
{
    switch(operation->driver_id) {
    #if IS_ACTIVE(CONFIG_PERIPH_HASHES)
        case PSA_CRYPTO_PERIPH_DRIVER_ID:
            return periph_hash_finish(&(operation->ctx.periph_ctx), hash, hash_size, hash_length);
    #endif

    #if IS_ACTIVE(CONFIG_MODULE_HASHES)
        case PSA_CRYPTO_BUILTIN_DRIVER_ID:
            return psa_builtin_hash_finish(operation, hash, hash_size, hash_length);
    #endif

    #if IS_ACTIVE(CONFIG_MODULE_CRYPTOAUTHLIB_HASHES)
        case PSA_CRYPTO_SE_DRIVER_ID:
            return atca_hash_finish(&(operation->ctx.atca_ctx), hash, hash_size, hash_length);
    #endif
        default:
            (void) hash;
            (void) hash_size;
            (void) hash_length;
            return PSA_ERROR_BAD_STATE;
    }
}
