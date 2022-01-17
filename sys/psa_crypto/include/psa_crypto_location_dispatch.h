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

#ifndef PSA_CRYPTO_LOCATION_DISPATCH_H
#define PSA_CRYPTO_LOCATION_DISPATCH_H

#include <stdlib.h>
#include "kernel_defines.h"
#include "psa/crypto.h"

psa_status_t psa_location_dispatch_sign_hash(  const psa_key_attributes_t *attributes,
                                            psa_algorithm_t alg,
                                            const uint8_t *key_buffer,
                                            size_t key_buffer_size,
                                            const uint8_t * hash,
                                            size_t hash_length,
                                            uint8_t * signature,
                                            size_t signature_size,
                                            size_t * signature_length);

psa_status_t psa_location_dispatch_verify_hash(  const psa_key_attributes_t *attributes,
                                            psa_algorithm_t alg,
                                            const uint8_t *key_buffer,
                                            size_t key_buffer_size,
                                            const uint8_t * hash,
                                            size_t hash_length,
                                            const uint8_t * signature,
                                            size_t signature_length);

psa_status_t psa_location_dispatch_mac_compute(const psa_key_attributes_t *attributes,
                                                psa_algorithm_t alg,
                                                const uint8_t * key_buffer,
                                                size_t key_buffer_size,
                                                const uint8_t * input,
                                                size_t input_length,
                                                uint8_t * mac,
                                                size_t mac_size,
                                                size_t * mac_length);

psa_status_t psa_location_dispatch_export_public_key(  const psa_key_attributes_t *attributes,
                                                    const uint8_t *key_buffer,
                                                    size_t key_buffer_size,
                                                    uint8_t * data,
                                                    size_t data_size,
                                                    size_t * data_length);

psa_status_t psa_location_dispatch_generate_key(   const psa_key_attributes_t *attributes,
                                                uint8_t *key_buffer, size_t key_buffer_size,
                                                size_t *key_buffer_length, uint8_t *pubkey_buffer, size_t pubkey_buffer_size, size_t *pubkey_buffer_length);

psa_status_t psa_location_dispatch_import_key( const psa_key_attributes_t *attributes,
                                            const uint8_t *data, size_t data_length,
                                            uint8_t *key_buffer, size_t key_buffer_size,
                                            size_t *key_buffer_length, size_t *bits);

psa_status_t psa_location_dispatch_cipher_encrypt_setup(   psa_cipher_operation_t *operation,
                                                        const psa_key_attributes_t *attributes,
                                                        const uint8_t *key_buffer,
                                                        size_t key_buffer_size,
                                                        psa_algorithm_t alg);

psa_status_t psa_location_dispatch_cipher_decrypt_setup(psa_cipher_operation_t *operation,
                                                    const psa_key_attributes_t *attributes,
                                                    const uint8_t *key_buffer,
                                                    size_t key_buffer_size,
                                                    psa_algorithm_t alg);

psa_status_t psa_location_dispatch_cipher_set_iv(  psa_cipher_operation_t *operation,
                                                const uint8_t *iv,
                                                size_t iv_length);

psa_status_t psa_location_dispatch_cipher_decrypt(  const psa_key_attributes_t * attributes,
                                                    psa_algorithm_t alg,
                                                    const uint8_t * key_buffer,
                                                    size_t key_buffer_size,
                                                    const uint8_t * input,
                                                    size_t input_length,
                                                    uint8_t * output,
                                                    size_t output_size,
                                                    size_t * output_length);

psa_status_t psa_location_dispatch_cipher_encrypt(  const psa_key_attributes_t * attributes,
                                                    psa_algorithm_t alg,
                                                    const uint8_t * key_buffer,
                                                    size_t key_buffer_size,
                                                    const uint8_t * input,
                                                    size_t input_length,
                                                    uint8_t * output,
                                                    size_t output_size,
                                                    size_t * output_length);

psa_status_t psa_location_dispatch_generate_random(uint8_t * output,
                                                size_t output_size);

#endif /* PSA_CRYPTOOCATION__LDISPATER_H */
