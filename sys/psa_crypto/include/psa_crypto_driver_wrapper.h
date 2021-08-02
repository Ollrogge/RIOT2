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
 * @brief       Funtion declarations for PSA Crypto Driver Wrapper
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#ifndef PSA_CRYPTO_DRIVER_WRAPPER_H
#define PSA_CRYPTO_DRIVER_WRAPPER_H

#include <stdlib.h>
#include "kernel_defines.h"
#include "psa/crypto.h"

psa_status_t psa_driver_wrapper_hash_setup(psa_hash_operation_t * operation,
                                           psa_algorithm_t alg);

psa_status_t psa_driver_wrapper_hash_update(psa_hash_operation_t * operation,
                                            const uint8_t * input,
                                            size_t input_length);

psa_status_t psa_driver_wrapper_hash_finish(psa_hash_operation_t * operation,
                                            uint8_t * hash,
                                            size_t hash_size,
                                            size_t * hash_length);

psa_status_t psa_driver_wrapper_import_key( const psa_key_attributes_t *attributes,
                                            const uint8_t *data, size_t data_length,
                                            uint8_t *key_buffer, size_t key_buffer_size,
                                            size_t *key_buffer_length, size_t *bits);

psa_status_t psa_driver_wrapper_cipher_encrypt_setup(   psa_cipher_operation_t *operation,
                                                        const psa_key_attributes_t *attributes,
                                                        const uint8_t *key_buffer,
                                                        size_t key_buffer_size,
                                                        psa_algorithm_t alg);

psa_status_t psa_driver_wrapper_cipher_decrypt_setup(   psa_cipher_operation_t *operation,
                                                        const psa_key_attributes_t *attributes,
                                                        const uint8_t *key_buffer,
                                                        size_t key_buffer_size,
                                                        psa_algorithm_t alg);

psa_status_t psa_driver_wrapper_cipher_set_iv(  psa_cipher_operation_t *operation,
                                                const uint8_t *iv,
                                                size_t iv_length);

psa_status_t psa_driver_wrapper_cipher_encrypt( psa_cipher_operation_t *operation,
                                                const psa_key_attributes_t *attributes,
                                                const uint8_t * input,
                                                size_t input_length,
                                                uint8_t * output,
                                                size_t output_size,
                                                size_t * output_length);

#endif /* PSA_CRYPTO_DRIVER_WRAPPER_H */
