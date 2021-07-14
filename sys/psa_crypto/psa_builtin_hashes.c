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

psa_status_t psa_builtin_hash_setup(psa_hash_operation_t * operation,
                                           psa_algorithm_t alg)
{
    switch(alg) {
    #if IS_ACTIVE(CONFIG_MODULE_BUILTIN_HASH_MD5)
        case PSA_ALG_MD5:
            md5_init(&(operation->ctx.builtin_ctx.md5));
            break;
    #endif
    #if IS_ACTIVE(CONFIG_MODULE_BUILTIN_HASH_SHA1)
        case PSA_ALG_SHA_1:
            sha1_init(&(operation->ctx.builtin_ctx.sha1));
            break;
    #endif
    #if IS_ACTIVE(CONFIG_MODULE_BUILTIN_HASH_SHA224)
        case PSA_ALG_SHA_224:
            sha224_init(&(operation->ctx.builtin_ctx.sha224));
            break;
    #endif
    #if IS_ACTIVE(CONFIG_MODULE_BUILTIN_HASH_SHA256)
        case PSA_ALG_SHA_256:
            sha256_init(&(operation->ctx.builtin_ctx.sha256));
            break;
    #endif
        default:
            (void) operation;
            return PSA_ERROR_NOT_SUPPORTED;
    }
    return PSA_SUCCESS;
}

psa_status_t psa_builtin_hash_update(psa_hash_operation_t * operation,
                             const uint8_t * input,
                             size_t input_length)
{
    switch(operation->alg) {
    #if IS_ACTIVE(CONFIG_MODULE_BUILTIN_HASH_MD5)
        case PSA_ALG_MD5:
            md5_update(&(operation->ctx.builtin_ctx.md5), input, input_length);
            break;
    #endif
    #if IS_ACTIVE(CONFIG_MODULE_BUILTIN_HASH_SHA1)
        case PSA_ALG_SHA_1:
            sha1_update(&(operation->ctx.builtin_ctx.sha1), input, input_length);
            break;
    #endif
    #if IS_ACTIVE(CONFIG_MODULE_BUILTIN_HASH_SHA224)
        case PSA_ALG_SHA_224:
            sha224_update(&(operation->ctx.builtin_ctx.sha224), input, input_length);
            break;
    #endif
    #if IS_ACTIVE(CONFIG_MODULE_BUILTIN_HASH_SHA256)
        case PSA_ALG_SHA_256:
            sha256_update(&(operation->ctx.builtin_ctx.sha256), input, input_length);
            break;
    #endif
        default:
            (void) input;
            (void) input_length;
            return PSA_ERROR_NOT_SUPPORTED;
    }

    return PSA_SUCCESS;
}

psa_status_t psa_builtin_hash_finish(psa_hash_operation_t * operation,
                             uint8_t * hash,
                             size_t hash_size,
                             size_t * hash_length)
{
    switch(operation->alg) {
    #if IS_ACTIVE(CONFIG_MODULE_BUILTIN_HASH_MD5)
        case PSA_ALG_MD5:
            md5_final(&(operation->ctx.builtin_ctx.md5), hash);
            break;
    #endif
    #if IS_ACTIVE(CONFIG_MODULE_BUILTIN_HASH_SHA1)
        case PSA_ALG_SHA_1:
            sha1_final(&(operation->ctx.builtin_ctx.sha1), hash);
            break;
    #endif
    #if IS_ACTIVE(CONFIG_MODULE_BUILTIN_HASH_SHA224)
        case PSA_ALG_SHA_224:
            sha224_final(&(operation->ctx.builtin_ctx.sha224), hash);
            break;
    #endif
    #if IS_ACTIVE(CONFIG_MODULE_BUILTIN_HASH_SHA256)
        case PSA_ALG_SHA_256:
            sha256_final(&(operation->ctx.builtin_ctx.sha256), hash);
            break;
    #endif
        default:
            (void) hash;
            return PSA_ERROR_NOT_SUPPORTED;
    }

    (void) hash_size;
    (void) hash_length;
    return PSA_SUCCESS;
}