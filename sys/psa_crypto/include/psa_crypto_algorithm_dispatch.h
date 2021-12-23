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
 * @brief       Funtion declarations for PSA Crypto Algorithm Dispatch
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#ifndef PSA_CRYPTO_ALGORITHM_DISPATCH_H
#define PSA_CRYPTO_ALGORITHM_DISPATCH_H

#include <stdlib.h>
#include "kernel_defines.h"
#include "psa/crypto.h"
#include "psa_crypto_slot_management.h"

psa_status_t psa_algorithm_dispatch_hash_setup(psa_hash_operation_t * operation,
                                           psa_algorithm_t alg);

psa_status_t psa_algorithm_dispatch_hash_update(psa_hash_operation_t * operation,
                                            const uint8_t * input,
                                            size_t input_length);

psa_status_t psa_algorithm_dispatch_hash_finish(psa_hash_operation_t * operation,
                                            uint8_t * hash,
                                            size_t hash_size,
                                            size_t * hash_length);

psa_status_t psa_algorithm_dispatch_sign_hash(  const psa_key_attributes_t *attributes,
                                            psa_algorithm_t alg,
                                            const uint8_t *key_buffer,
                                            size_t key_buffer_size,
                                            const uint8_t * hash,
                                            size_t hash_length,
                                            uint8_t * signature,
                                            size_t signature_size,
                                            size_t * signature_length);

psa_status_t psa_algorithm_dispatch_verify_hash(  const psa_key_attributes_t *attributes,
                                            psa_algorithm_t alg,
                                            const uint8_t *key_buffer,
                                            size_t key_buffer_size,
                                            const uint8_t * hash,
                                            size_t hash_length,
                                            const uint8_t * signature,
                                            size_t signature_length);

psa_status_t psa_algorithm_dispatch_generate_key(   const psa_key_attributes_t *attributes,
                                                uint8_t *key_buffer, size_t key_buffer_size,
                                                size_t *key_buffer_length, uint8_t *pubkey_buffer, size_t pubkey_buffer_size, size_t *pubkey_buffer_length);

psa_status_t psa_algorithm_dispatch_cipher_encrypt( psa_key_slot_t *slot,
                                            psa_algorithm_t alg,
                                            const uint8_t * input,
                                            size_t input_length,
                                            uint8_t * output,
                                            size_t output_size,
                                            size_t * output_length);

#endif /* PSA_ALGORITHM_DISPATCH_H */