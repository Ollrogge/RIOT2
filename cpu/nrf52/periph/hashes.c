/*
 * Copyright (C) 2021 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     sys_psa_crypto cpu_nrf52
 * @{
 *
 * @file
 * @brief       Glue code for ARM Cryptocell driver support in PSA Crypto
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#include <stdio.h>
#include "kernel_defines.h"
#include "psa/crypto.h"
#include "periph_hashes.h"
#include "cryptocell_util.h"
#include "cryptocell_incl/crys_hash.h"
#include "cryptocell_incl/crys_hash_error.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

#define CC310_MAX_HASH_INPUT_BLOCK       (0xFFF0)

static psa_status_t cc310_to_psa_error(CRYSError_t error)
{
    switch(error) {
        case CRYS_HASH_ILLEGAL_OPERATION_MODE_ERROR:
        case CRYS_HASH_IS_NOT_SUPPORTED:
            return PSA_ERROR_NOT_SUPPORTED;
        case CRYS_HASH_USER_CONTEXT_CORRUPTED_ERROR:
            return PSA_ERROR_CORRUPTION_DETECTED;
        case CRYS_HASH_DATA_IN_POINTER_INVALID_ERROR:
        case CRYS_HASH_DATA_SIZE_ILLEGAL:
            return PSA_ERROR_DATA_INVALID;
        case CRYS_HASH_INVALID_RESULT_BUFFER_POINTER_ERROR:
        case CRYS_HASH_ILLEGAL_PARAMS_ERROR:
        case CRYS_HASH_INVALID_USER_CONTEXT_POINTER_ERROR:
        case CRYS_HASH_LAST_BLOCK_ALREADY_PROCESSED_ERROR:
        case CRYS_HASH_CTX_SIZES_ERROR:
            return PSA_ERROR_INVALID_ARGUMENT;
        default:
            return PSA_ERROR_GENERIC_ERROR;
    }
}

psa_status_t periph_hash_setup(psa_hash_periph_operation_t * operation,
                                           psa_algorithm_t alg)
{
    DEBUG("Cryptocell Setup\n");
    if (operation->alg != 0) {
        return PSA_ERROR_BAD_STATE;
    }

    int ret = 0;
    switch(alg) {
#if IS_ACTIVE(CONFIG_PERIPH_HASH_SHA1)
        case PSA_ALG_SHA_1:
            ret = CRYS_HASH_Init(&operation->ctx, CRYS_HASH_SHA1_mode);
            break;
#endif
#if IS_ACTIVE(CONFIG_PERIPH_HASH_SHA224)
        case PSA_ALG_SHA_224:
            ret = CRYS_HASH_Init(&operation->ctx, CRYS_HASH_SHA224_mode);
            break;
#endif
#if IS_ACTIVE(CONFIG_PERIPH_HASH_SHA256)
        case PSA_ALG_SHA_256:
            ret = CRYS_HASH_Init(&operation->ctx, CRYS_HASH_SHA256_mode);
            break;
#endif
        default:
            (void) operation;
            return PSA_ERROR_NOT_SUPPORTED;
    }

    if (ret != CRYS_OK) {
        return cc310_to_psa_error(ret);
    }

    operation->alg = alg;
    return PSA_SUCCESS;
}

psa_status_t periph_hash_update(psa_hash_periph_operation_t * operation,
                             const uint8_t * input,
                             size_t input_length)
{
    if (operation->alg == 0) {
        return PSA_ERROR_BAD_STATE;
    }

    int ret = 0;
    size_t offset = 0;
    size_t size;
    do {
        if (input_length > CC310_MAX_HASH_INPUT_BLOCK) {
            size = CC310_MAX_HASH_INPUT_BLOCK;
            input_length -= CC310_MAX_HASH_INPUT_BLOCK;
        }
        else {
            size = input_length;
            input_length = 0;
        }

        cryptocell_enable();
        ret = CRYS_HASH_Update(&operation->ctx, (uint8_t*)(input + offset), size);
        cryptocell_disable();

        offset += size;
    } while ((input_length > 0) && (ret == CRYS_OK));

    if (ret != CRYS_OK) {
        return cc310_to_psa_error(ret);
    }
    return PSA_SUCCESS;
}

psa_status_t periph_hash_finish(psa_hash_periph_operation_t * operation,
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

    int ret = 0;
    cryptocell_enable();
    ret = CRYS_HASH_Finish(&operation->ctx, (uint32_t*)hash);
    cryptocell_disable();

    if (ret != CRYS_OK) {
        return cc310_to_psa_error(ret);
    }
    *hash_length = actual_hash_length;
    return PSA_SUCCESS;
}