/*
 * Copyright (C) 2021 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     pkg_cryptoauthlib sys_psa_crypto
 * @{
 *
 * @file
 * @brief       Glue code for ATCA driver support in PSA Crypto
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#include "psa/crypto.h"
#include "cryptoauthlib.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

static psa_status_t atca_to_psa_error(ATCA_STATUS error)
{
    DEBUG("ATCA Error: 0x%x\n", error);
    switch(error) {
        case ATCA_NOT_LOCKED:
        case ATCA_EXECUTION_ERROR:
        case ATCA_FUNC_FAIL:
            return PSA_ERROR_BAD_STATE;
        case ATCA_WAKE_FAILED:
        case ATCA_RX_FAIL:
        case ATCA_RX_NO_RESPONSE:
        case ATCA_TX_TIMEOUT:
        case ATCA_RX_TIMEOUT:
        case ATCA_TOO_MANY_COMM_RETRIES:
        case ATCA_COMM_FAIL:
        case ATCA_TIMEOUT:
        case ATCA_TX_FAIL:
            return PSA_ERROR_COMMUNICATION_FAILURE;
        case ATCA_RX_CRC_ERROR:
        case ATCA_STATUS_CRC:
            return PSA_ERROR_DATA_CORRUPT;
        case ATCA_SMALL_BUFFER:
            return PSA_ERROR_BUFFER_TOO_SMALL;
        case ATCA_BAD_OPCODE:
        case ATCA_BAD_PARAM:
        case ATCA_INVALID_SIZE:
        case ATCA_INVALID_ID:
            return PSA_ERROR_INVALID_ARGUMENT;
        case ATCA_UNIMPLEMENTED:
            return PSA_ERROR_NOT_SUPPORTED;
        default:
            return PSA_ERROR_GENERIC_ERROR;
    }
}

psa_status_t atca_hash_setup(psa_hash_atca_operation_t * operation,
                                           psa_algorithm_t alg)
{
    DEBUG("Cryptoauth Setup\n");
    if (operation->alg != 0) {
        return PSA_ERROR_BAD_STATE;
    }

    int status = PSA_ERROR_GENERIC_ERROR;

    if (alg != PSA_ALG_SHA_256) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    status = atcab_hw_sha2_256_init(&operation->ctx);

    if (status != ATCA_SUCCESS) {
        return atca_to_psa_error(status);
    }
    operation->alg = alg;

    return PSA_SUCCESS;
}

psa_status_t atca_hash_update(psa_hash_atca_operation_t * operation,
                             const uint8_t * input,
                             size_t input_length)
{
    if (operation->alg == 0) {
        return PSA_ERROR_BAD_STATE;
    }

    if (operation->alg != PSA_ALG_SHA_256) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    int status = PSA_ERROR_GENERIC_ERROR;

    status = atcab_hw_sha2_256_update(&operation->ctx, input, input_length);

    if (status != ATCA_SUCCESS) {
        return atca_to_psa_error(status);
    }

    return PSA_SUCCESS;
}

psa_status_t atca_hash_finish(psa_hash_atca_operation_t * operation,
                             uint8_t * hash,
                             size_t hash_size,
                             size_t * hash_length)
{
    if (operation->alg == 0) {
        return PSA_ERROR_BAD_STATE;
    }

    if (operation->alg != PSA_ALG_SHA_256) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    int status = PSA_ERROR_GENERIC_ERROR;
    uint8_t actual_hash_length = PSA_HASH_LENGTH(operation->alg);

    if (hash_size < actual_hash_length) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    status = atcab_hw_sha2_256_finish(&operation->ctx, hash);

    if (status != ATCA_SUCCESS) {
        return atca_to_psa_error(status);
    }

    *hash_length = actual_hash_length;
    return PSA_SUCCESS;
}
