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
#include "tinycrypt/aes.h"
#include "tinycrypt/cbc_mode.h"
#include "tinycrypt/constants.h"

#define AES_128_BLOCK_SIZE      (16)
#define AES_128_KEY_SIZE        (16)

#define ALG_IS_SUPPORTED(alg)   \
    (   (alg == PSA_ALG_ECB_NO_PADDING) || \
        (alg == PSA_ALG_CBC_NO_PADDING))

psa_status_t psa_software_cipher_encrypt_setup(  psa_software_cipher_operation_t * operation,
                                                const psa_key_attributes_t *attributes,
                                                const uint8_t *key_buffer,
                                                size_t key_buffer_size,
                                                psa_algorithm_t alg)
{
    int status;
    if (attributes->type != PSA_KEY_TYPE_AES ||
        !ALG_IS_SUPPORTED(alg) ||
        (key_buffer_size != AES_128_KEY_SIZE)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    status = tc_aes128_set_encrypt_key(&operation->tc_aes, key_buffer);
    if (status != TC_CRYPTO_SUCCESS) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    operation->alg = alg;

    return PSA_SUCCESS;
}

psa_status_t psa_software_cipher_decrypt_setup(  psa_software_cipher_operation_t * operation,
                                                const psa_key_attributes_t *attributes,
                                                const uint8_t *key_buffer,
                                                size_t key_buffer_size,
                                                psa_algorithm_t alg)
{
    int status;
    if (attributes->type != PSA_KEY_TYPE_AES ||
        !ALG_IS_SUPPORTED(alg) ||
        (key_buffer_size != AES_128_KEY_SIZE)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    status = tc_aes128_set_decrypt_key(&operation->tc_aes, key_buffer);
    if (status != TC_CRYPTO_SUCCESS) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    return PSA_SUCCESS;
}

static psa_status_t tc_aes_ecb_encrypt(TCAesKeySched_t ctx, const uint8_t *input, size_t input_size, uint8_t *output)
{
    int status;
    size_t offset = 0;

    do {
        status = tc_aes_encrypt(output + offset, input + offset, ctx);
        if (status != TC_CRYPTO_SUCCESS) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }

        offset += AES_128_BLOCK_SIZE;
    } while (offset < input_size);

    return PSA_SUCCESS;
}

psa_status_t psa_software_cipher_encrypt(psa_cipher_operation_t * operation,
                                        const uint8_t * input,
                                        size_t input_length,
                                        uint8_t * output,
                                        size_t output_size,
                                        size_t * output_length)
{
    int ret;
    psa_software_cipher_operation_t *sw_op = &operation->ctx.sw_ctx;

    if (input_length % AES_128_BLOCK_SIZE != 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    switch(sw_op->alg) {
        case PSA_ALG_ECB_NO_PADDING:
            return tc_aes_ecb_encrypt(&sw_op->tc_aes, input, input_length, output);
        case PSA_ALG_CBC_NO_PADDING:
            ret = tc_cbc_mode_encrypt(output, output_size, input, input_length, output, &sw_op->tc_aes);
            if (ret != TC_CRYPTO_SUCCESS) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
            break;
        default:
            return PSA_ERROR_NOT_SUPPORTED;
    }

    *output_length = output_size;

    return PSA_SUCCESS;
}
