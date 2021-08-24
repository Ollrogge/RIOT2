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
    (   (alg == PSA_ALG_CBC_NO_PADDING))

psa_status_t psa_cipher_aes_cbc_encrypt(const psa_key_attributes_t *attributes,
                                        const uint8_t *key_buffer,
                                        size_t key_buffer_size,
                                        psa_algorithm_t alg,
                                        const uint8_t * input,
                                        size_t input_length,
                                        uint8_t * output,
                                        size_t output_size,
                                        size_t * output_length)
{
    int ret;
    psa_status_t status;
    size_t iv_length = 0;
    psa_cipher_operation_t operation = psa_cipher_operation_init();
    operation.iv_required = 1;
    operation.default_iv_length = PSA_CIPHER_IV_LENGTH(attributes->type, alg);

    if (attributes->type != PSA_KEY_TYPE_AES ||
        !ALG_IS_SUPPORTED(alg) ||
        (key_buffer_size != AES_128_KEY_SIZE)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (input_length % AES_128_BLOCK_SIZE != 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    ret = tc_aes128_set_encrypt_key(&operation.ctx.aes, key_buffer);
    if (ret != TC_CRYPTO_SUCCESS) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = psa_cipher_generate_iv(&operation, output, operation.default_iv_length, &iv_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    ret = tc_cbc_mode_encrypt(output, output_size, input, input_length, output, &operation.ctx.aes);
    if (ret != TC_CRYPTO_SUCCESS) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    *output_length = output_size;

    return PSA_SUCCESS;
}
