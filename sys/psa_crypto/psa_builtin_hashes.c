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

psa_status_t psa_builtin_hash_setup(psa_builtin_hash_operation_t * operation,
                                           psa_algorithm_t alg)
{
    if (operation->alg != 0) {
        return PSA_ERROR_BAD_STATE;
    }

    switch(alg) {
    #if IS_ACTIVE(CONFIG_SW_HASH_MD5)
        case PSA_ALG_MD5:
            md5_init(&(operation->ctx.md5));
            break;
    #endif
    #if IS_ACTIVE(CONFIG_SW_HASH_SHA1)
        case PSA_ALG_SHA_1:
            sha1_init(&(operation->ctx.sha1));
            break;
    #endif
    #if IS_ACTIVE(CONFIG_SW_HASH_SHA224)
        case PSA_ALG_SHA_224:
            sha224_init(&(operation->ctx.sha224));
            break;
    #endif
    #if IS_ACTIVE(CONFIG_SW_HASH_SHA256)
        case PSA_ALG_SHA_256:
            sha256_init(&(operation->ctx.sha256));
            break;
    #endif
        default:
            return PSA_ERROR_NOT_SUPPORTED;
    }

    operation->alg = alg;

    return PSA_SUCCESS;
}

psa_status_t psa_builtin_hash_update(psa_builtin_hash_operation_t * operation,
                             const uint8_t * input,
                             size_t input_length)
{
    if (operation->alg == 0) {
        return PSA_ERROR_BAD_STATE;
    }

    switch(operation->alg) {
    #if IS_ACTIVE(CONFIG_SW_HASH_MD5)
        case PSA_ALG_MD5:
            md5_update(&(operation->ctx.md5), input, input_length);
            break;
    #endif
    #if IS_ACTIVE(CONFIG_SW_HASH_SHA1)
        case PSA_ALG_SHA_1:
            sha1_update(&(operation->ctx.sha1), input, input_length);
            break;
    #endif
    #if IS_ACTIVE(CONFIG_SW_HASH_SHA224)
        case PSA_ALG_SHA_224:
            sha224_update(&(operation->ctx.sha224), input, input_length);
            break;
    #endif
    #if IS_ACTIVE(CONFIG_SW_HASH_SHA256)
        case PSA_ALG_SHA_256:
            sha256_update(&(operation->ctx.sha256), input, input_length);
            break;
    #endif
        default:
            (void) input;
            (void) input_length;
            return PSA_ERROR_NOT_SUPPORTED;
    }

    return PSA_SUCCESS;
}

psa_status_t psa_builtin_hash_finish(psa_builtin_hash_operation_t * operation,
                             uint8_t * hash,
                             size_t hash_size,
                             size_t * hash_length)
{
    if (operation->alg == 0) {
        return PSA_ERROR_BAD_STATE;
    }

    uint8_t actual_hash_length = PSA_HASH_LENGTH(operation->alg);

    if (hash_size < actual_hash_length) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    switch(operation->alg) {
    #if IS_ACTIVE(CONFIG_SW_HASH_MD5)
        case PSA_ALG_MD5:
            md5_final(&(operation->ctx.md5), hash);
            break;
    #endif
    #if IS_ACTIVE(CONFIG_SW_HASH_SHA1)
        case PSA_ALG_SHA_1:
            sha1_final(&(operation->ctx.sha1), hash);
            break;
    #endif
    #if IS_ACTIVE(CONFIG_SW_HASH_SHA224)
        case PSA_ALG_SHA_224:
            sha224_final(&(operation->ctx.sha224), hash);
            break;
    #endif
    #if IS_ACTIVE(CONFIG_SW_HASH_SHA256)
        case PSA_ALG_SHA_256:
            sha256_final(&(operation->ctx.sha256), hash);
            break;
    #endif
        default:
            (void) hash;
            return PSA_ERROR_NOT_SUPPORTED;
    }

    *hash_length = actual_hash_length;
    return PSA_SUCCESS;
}