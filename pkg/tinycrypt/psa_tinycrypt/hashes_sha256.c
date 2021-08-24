/*
 * Copyright (C) 2021 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     sys_psa_crypto pkg_tinycrypt
 * @{
 *
 * @file
 * @brief
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */
#include <stdio.h>
#include "psa/crypto.h"
#include "tinycrypt/sha256.h"
#include "tinycrypt/constants.h"

psa_status_t psa_hashes_sha256_setup(psa_hashes_sha256_ctx_t * ctx)
{
    int status;

    status = tc_sha256_init((struct tc_sha256_state_struct *) ctx);
    if (status != TC_CRYPTO_SUCCESS) {
        /* Init fails, when a Nullpointer is passed, which translates to
        an invalid argument error */
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    return PSA_SUCCESS;
}

psa_status_t psa_hashes_sha256_update(psa_hashes_sha256_ctx_t * ctx,
                             const uint8_t * input,
                             size_t input_length)
{
    int status;

    status = tc_sha256_update((struct tc_sha256_state_struct *) ctx, input, input_length);

    if (status != TC_CRYPTO_SUCCESS) {
        /* Update fails, when a Nullpointer is passed, which translates to
        an invalid argument error */
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    return PSA_SUCCESS;
}

psa_status_t psa_hashes_sha256_finish(psa_hashes_sha256_ctx_t * ctx,
                             uint8_t * hash,
                             size_t hash_size,
                             size_t * hash_length)
{
    int status;

    status = tc_sha256_final(hash, (struct tc_sha256_state_struct *) ctx);

    if (status != TC_CRYPTO_SUCCESS) {
        /* Final fails, when a Nullpointer is passed, which translates to
        an invalid argument error */
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    (void) hash_size;
    (void) hash_length;
    return PSA_SUCCESS;
}
