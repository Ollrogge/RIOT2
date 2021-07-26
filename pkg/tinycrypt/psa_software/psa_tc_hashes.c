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
 * @brief       Meta API for RIOT software hashes for PSA Crypto
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#include "psa/crypto.h"

#include "tinycrypt/sha256.h"

psa_status_t psa_software_hash_setup(psa_hash_operation_t * operation,
                                           psa_algorithm_t alg)
{
    int status;

    /* Tinycrypt only supports SHA256 operations */
    if (alg != PSA_ALG_SHA_256)
        return PSA_ERROR_NOT_SUPPORTED;
    }

    status = tc_sha256_init(operation->ctx.sw_ctx.tc_sha256);
    if (status != TC_CRYPTO_SUCCESS) {
        /* Init fails, when a Nullpointer is passed, which translates to
        an invalid argument error */
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    return PSA_SUCCESS;
}

psa_status_t psa_software_hash_update(psa_hash_operation_t * operation,
                             const uint8_t * input,
                             size_t input_length)
{
    int status;
    if (operation->alg != PSA_ALG_SHA_256)
        return PSA_ERROR_NOT_SUPPORTED;
    }

    status = tc_sha256_update(operation->ctx.sw_ctx.tc_sha256, input, input_length);

    if (status != TC_CRYPTO_SUCCESS) {
        /* Update fails, when a Nullpointer is passed, which translates to
        an invalid argument error */
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    return PSA_SUCCESS;
}

psa_status_t psa_software_hash_finish(psa_hash_operation_t * operation,
                             uint8_t * hash,
                             size_t hash_size,
                             size_t * hash_length)
{
    int status;
    if (operation->alg != PSA_ALG_SHA_256)
        return PSA_ERROR_NOT_SUPPORTED;
    }

    status = tc_sha256_final(hash, operation->ctx.sw_ctx.tc_sha256);

    if (status != TC_CRYPTO_SUCCESS) {
        /* Final fails, when a Nullpointer is passed, which translates to
        an invalid argument error */
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    (void) hash_size;
    (void) hash_length;
    return PSA_SUCCESS;
}
