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
 * @brief       PSA Crypto API implementation
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#include <stdio.h>
#include "psa/crypto.h"
#include "include/psa_crypto_se_driver.h"
#include "include/psa_crypto_se_management.h"
#include "include/psa_crypto_slot_management.h"
#include "include/psa_crypto_driver_wrapper.h"

#include "kernel_defines.h"

static uint8_t lib_initialized = 0;

/* constant-time buffer comparison */
static inline int safer_memcmp(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;

    for (size_t i = 0; i < n; i++)
        diff |= a[i] ^ b[i];

    return diff;
}

psa_status_t psa_crypto_init(void)
{
    lib_initialized = 1;
    return PSA_SUCCESS;
}

psa_status_t psa_aead_abort(psa_aead_operation_t * operation)
{
    (void) operation;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_aead_decrypt(psa_key_id_t key,
                              psa_algorithm_t alg,
                              const uint8_t * nonce,
                              size_t nonce_length,
                              const uint8_t * additional_data,
                              size_t additional_data_length,
                              const uint8_t * ciphertext,
                              size_t ciphertext_length,
                              uint8_t * plaintext,
                              size_t plaintext_size,
                              size_t * plaintext_length)
{
    (void) key;
    (void) alg;
    (void) nonce;
    (void) nonce_length;
    (void) additional_data;
    (void) additional_data_length;
    (void) ciphertext;
    (void) ciphertext_length;
    (void) plaintext;
    (void) plaintext_size;
    (void) plaintext_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_aead_decrypt_setup(psa_aead_operation_t * operation,
                                    psa_key_id_t key,
                                    psa_algorithm_t alg)
{
    (void) operation;
    (void) key;
    (void) alg;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_aead_encrypt(psa_key_id_t key,
                              psa_algorithm_t alg,
                              const uint8_t * nonce,
                              size_t nonce_length,
                              const uint8_t * additional_data,
                              size_t additional_data_length,
                              const uint8_t * plaintext,
                              size_t plaintext_length,
                              uint8_t * ciphertext,
                              size_t ciphertext_size,
                              size_t * ciphertext_length)
{
    (void) key;
    (void) alg;
    (void) nonce;
    (void) nonce_length;
    (void) additional_data;
    (void) additional_data_length;
    (void) plaintext;
    (void) plaintext_length;
    (void) ciphertext;
    (void) ciphertext_size;
    (void) ciphertext_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_aead_encrypt_setup(psa_aead_operation_t * operation,
                                    psa_key_id_t key,
                                    psa_algorithm_t alg)
{
    (void) operation;
    (void) key;
    (void) alg;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_aead_finish(psa_aead_operation_t * operation,
                             uint8_t * ciphertext,
                             size_t ciphertext_size,
                             size_t * ciphertext_length,
                             uint8_t * tag,
                             size_t tag_size,
                             size_t * tag_length)
{
    (void) operation;
    (void) ciphertext;
    (void) ciphertext_size;
    (void) ciphertext_length;
    (void) tag;
    (void) tag_size;
    (void) tag_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_aead_generate_nonce(psa_aead_operation_t * operation,
                                     uint8_t * nonce,
                                     size_t nonce_size,
                                     size_t * nonce_length)
{
    (void) operation;
    (void) nonce;
    (void) nonce_size;
    (void) nonce_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_aead_operation_t psa_aead_operation_init(void)
{
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_aead_set_lengths(psa_aead_operation_t * operation,
                                  size_t ad_length,
                                  size_t plaintext_length)
{   (void) operation;
    (void) ad_length;
    (void) plaintext_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_aead_set_nonce(psa_aead_operation_t * operation,
                                const uint8_t * nonce,
                                size_t nonce_length)
{
    (void) operation;
    (void) nonce;
    (void) nonce_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_aead_update(psa_aead_operation_t * operation,
                             const uint8_t * input,
                             size_t input_length,
                             uint8_t * output,
                             size_t output_size,
                             size_t * output_length)
{
    (void) operation;
    (void) input;
    (void) input_length;
    (void) output;
    (void) output_size;
    (void) output_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_aead_update_ad(psa_aead_operation_t * operation,
                                const uint8_t * input,
                                size_t input_length)
{
    (void) operation;
    (void) input;
    (void) input_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_aead_verify(psa_aead_operation_t * operation,
                             uint8_t * plaintext,
                             size_t plaintext_size,
                             size_t * plaintext_length,
                             const uint8_t * tag,
                             size_t tag_length)
{
    (void) operation;
    (void) plaintext;
    (void) plaintext_size;
    (void) plaintext_length;
    (void) tag;
    (void) tag_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_asymmetric_decrypt(psa_key_id_t key,
                                    psa_algorithm_t alg,
                                    const uint8_t * input,
                                    size_t input_length,
                                    const uint8_t * salt,
                                    size_t salt_length,
                                    uint8_t * output,
                                    size_t output_size,
                                    size_t * output_length)
{
    (void) key;
    (void) alg;
    (void) input;
    (void) input_length;
    (void) salt;
    (void) salt_length;
    (void) output;
    (void) output_size;
    (void) output_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_asymmetric_encrypt(psa_key_id_t key,
                                    psa_algorithm_t alg,
                                    const uint8_t * input,
                                    size_t input_length,
                                    const uint8_t * salt,
                                    size_t salt_length,
                                    uint8_t * output,
                                    size_t output_size,
                                    size_t * output_length)
{
    (void) key;
    (void) alg;
    (void) input;
    (void) input_length;
    (void) salt;
    (void) salt_length;
    (void) output;
    (void) output_size;
    (void) output_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

/* Ciphers */

static int psa_key_algorithm_permits(psa_key_type_t type, psa_algorithm_t policy_alg, psa_algorithm_t requested_alg)
{
    if (requested_alg == policy_alg) {
        return 1;
    }
    (void) type;
    return 0;
}

static psa_status_t psa_key_policy_permits( const psa_key_policy_t *policy, psa_key_type_t type, psa_algorithm_t alg)
{
    if (alg == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (psa_key_algorithm_permits(type, policy->alg, alg)) {
        return PSA_SUCCESS;
    }
    else {
        return PSA_ERROR_NOT_PERMITTED;
    }
}

static psa_status_t psa_get_and_lock_key_slot_with_policy(
    psa_key_id_t id,
    psa_key_slot_t **p_slot,
    psa_key_usage_t usage,
    psa_algorithm_t alg)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot;

    status = psa_get_and_lock_key_slot(id, p_slot);
    if (status != PSA_SUCCESS) {
        return status;
    }
    slot = *p_slot;

    if ((slot->attr.policy.usage & usage) != usage) {
        *p_slot = NULL;
        psa_unlock_key_slot(slot);
        return PSA_ERROR_NOT_PERMITTED;
    }

    if (alg != 0) {
        status = psa_key_policy_permits( &slot->attr.policy, slot->attr.type, alg);
        if (status != PSA_SUCCESS) {
            *p_slot = NULL;
            psa_unlock_key_slot(slot);
            return status;
        }
    }
    return PSA_SUCCESS;
}

psa_status_t psa_cipher_abort(psa_cipher_operation_t * operation)
{
    (void) operation;
    return PSA_ERROR_NOT_SUPPORTED;
}

static psa_status_t psa_cipher_setup(   psa_cipher_operation_t * operation,
                                        psa_key_id_t key,
                                        psa_algorithm_t alg,
                                        cipher_operation_t cipher_operation)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_status_t unlock_status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot;
    psa_key_usage_t usage = (   cipher_operation == PSA_CIPHER_ENCRYPT ?
                                PSA_KEY_USAGE_ENCRYPT :
                                PSA_KEY_USAGE_DECRYPT );

    if (operation->driver_id != 0) {
        return PSA_ERROR_BAD_STATE;
    }

    if (!PSA_ALG_IS_CIPHER(alg)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = psa_get_and_lock_key_slot_with_policy(key, &slot, usage, alg);
    if (status != PSA_SUCCESS) {
        psa_cipher_abort(operation);
        unlock_status = psa_unlock_key_slot(slot);
        return status;
    }

    operation->iv_set = 0;
    if (alg == PSA_ALG_ECB_NO_PADDING) {
        operation->iv_required = 0;
    }
    else {
        operation->iv_required = 1;
    }
    operation->default_iv_length = PSA_CIPHER_IV_LENGTH(slot->attr.type, alg);

    psa_key_attributes_t attr = slot->attr;

    if (cipher_operation == PSA_CIPHER_ENCRYPT) {
        status = psa_driver_wrapper_cipher_encrypt_setup(operation, &attr, slot->key.data, slot->key.bytes, alg);
    }
    else if (cipher_operation == PSA_CIPHER_DECRYPT) {
        status = psa_driver_wrapper_cipher_decrypt_setup(operation, &attr, slot->key.data, slot->key.bytes, alg);
    }

    if (status != PSA_SUCCESS) {
        psa_cipher_abort(operation);
    }

    unlock_status = psa_unlock_key_slot(slot);
    return ((status == PSA_SUCCESS) ? unlock_status : status);
}

psa_status_t psa_cipher_decrypt(psa_key_id_t key,
                                psa_algorithm_t alg,
                                const uint8_t * input,
                                size_t input_length,
                                uint8_t * output,
                                size_t output_size,
                                size_t * output_length)
{
    (void) key;
    (void) alg;
    (void) input;
    (void) input_length;
    (void) output;
    (void) output_size;
    (void) output_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_cipher_decrypt_setup(psa_cipher_operation_t * operation,
                                      psa_key_id_t key,
                                      psa_algorithm_t alg)
{
    return psa_cipher_setup(operation, key, alg, PSA_CIPHER_DECRYPT);
}

psa_status_t psa_cipher_encrypt(psa_key_id_t key,
                                psa_algorithm_t alg,
                                const uint8_t * input,
                                size_t input_length,
                                uint8_t * output,
                                size_t output_size,
                                size_t * output_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_cipher_operation_t operation = psa_cipher_operation_init();
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_get_key_attributes(key, &attr);
    status = psa_cipher_encrypt_setup(&operation, key, alg);
    if (status != PSA_SUCCESS) {
        return status;
    }

    return psa_driver_wrapper_cipher_encrypt(&operation, &attr, input, input_length, output, output_size, output_length);
}

psa_status_t psa_cipher_encrypt_setup(psa_cipher_operation_t * operation,
                                      psa_key_id_t key,
                                      psa_algorithm_t alg)
{
    return psa_cipher_setup(operation, key, alg, PSA_CIPHER_ENCRYPT);
}

psa_status_t psa_cipher_finish(psa_cipher_operation_t * operation,
                               uint8_t * output,
                               size_t output_size,
                               size_t * output_length)
{
    (void) operation;
    (void) output;
    (void) output_size;
    (void) output_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_cipher_generate_iv(psa_cipher_operation_t * operation,
                                    uint8_t * iv,
                                    size_t iv_size,
                                    size_t * iv_length)
{
    (void) operation;
    (void) iv;
    (void) iv_size;
    (void) iv_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_cipher_set_iv(psa_cipher_operation_t * operation,
                               const uint8_t * iv,
                               size_t iv_length)
{
    (void) operation;
    (void) iv;
    (void) iv_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_cipher_update(psa_cipher_operation_t * operation,
                               const uint8_t * input,
                               size_t input_length,
                               uint8_t * output,
                               size_t output_size,
                               size_t * output_length)
{
    (void) operation;
    (void) input;
    (void) input_length;
    (void) output;
    (void) output_size;
    (void) output_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_copy_key(psa_key_id_t source_key,
                          const psa_key_attributes_t * attributes,
                          psa_key_id_t * target_key)
{
    (void) source_key;
    (void) attributes;
    (void) target_key;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_destroy_key(psa_key_id_t key)
{
    (void) key;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_export_key(psa_key_id_t key,
                            uint8_t * data,
                            size_t data_size,
                            size_t * data_length)
{
    (void) key;
    (void) data;
    (void) data_size;
    (void) data_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_export_public_key(psa_key_id_t key,
                                   uint8_t * data,
                                   size_t data_size,
                                   size_t * data_length)
{
    (void) key;
    (void) data;
    (void) data_size;
    (void) data_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_generate_key(const psa_key_attributes_t * attributes,
                              psa_key_id_t * key)
{
    (void) attributes;
    (void) key;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_generate_random(uint8_t * output,
                                 size_t output_size)
{
    (void) output;
    (void) output_size;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_algorithm_t psa_get_key_algorithm(const psa_key_attributes_t * attributes)
{
    return attributes->policy.alg;
}

psa_status_t psa_get_key_attributes(psa_key_id_t key,
                                    psa_key_attributes_t * attributes)
{
    psa_status_t status;
    psa_key_slot_t *slot = NULL;

    status = psa_get_and_lock_key_slot(key, &slot);
    if (status != PSA_SUCCESS) {
        return status;
    }

    *attributes = slot->attr;

    status = psa_unlock_key_slot(slot);
    return status;
}

size_t psa_get_key_bits(const psa_key_attributes_t * attributes)
{
    return attributes->bits;
}

psa_key_id_t psa_get_key_id(const psa_key_attributes_t * attributes)
{
    return attributes->id;
}

psa_key_lifetime_t psa_get_key_lifetime(const psa_key_attributes_t * attributes)
{
    return attributes->lifetime;
}

psa_key_type_t psa_get_key_type(const psa_key_attributes_t * attributes)
{
    return attributes->type;
}

psa_key_usage_t psa_get_key_usage_flags(const psa_key_attributes_t * attributes)
{
    return attributes->policy.usage;
}

psa_status_t psa_hash_setup(psa_hash_operation_t * operation,
                            psa_algorithm_t alg)
{
    if (operation->alg != 0) {
        return PSA_ERROR_BAD_STATE;
    }

    if (!PSA_ALG_IS_HASH(alg)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    psa_status_t status = psa_driver_wrapper_hash_setup(operation, alg);
    if (status == PSA_SUCCESS) {
        operation->alg = alg;
    }

    return status;
}

psa_status_t psa_hash_update(psa_hash_operation_t * operation,
                             const uint8_t * input,
                             size_t input_length)
{
    if (operation->alg == 0) {
        return PSA_ERROR_BAD_STATE;
    }

    psa_status_t status = psa_driver_wrapper_hash_update(operation, input, input_length);

    if (status != PSA_SUCCESS) {
        psa_hash_abort(operation);
    }
    return status;
}

psa_status_t psa_hash_finish(psa_hash_operation_t * operation,
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

    psa_status_t status = psa_driver_wrapper_hash_finish(operation, hash, hash_size, hash_length);

    if (status == PSA_SUCCESS) {
        *hash_length = actual_hash_length;
    }

    /* Make sure operation becomes inactive after successfull execution */
    psa_hash_abort(operation);

    return status;
}

psa_status_t psa_hash_verify(psa_hash_operation_t * operation,
                             const uint8_t * hash,
                             size_t hash_length)
{
    int status = PSA_ERROR_CORRUPTION_DETECTED;
    uint8_t digest[PSA_HASH_MAX_SIZE];
    size_t actual_hash_length = 0;

    status = psa_hash_finish(operation, digest, PSA_HASH_MAX_SIZE, &actual_hash_length);

    if (status != PSA_SUCCESS) {
        return status;
    }

    if (actual_hash_length != hash_length) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    if (safer_memcmp(hash, digest, hash_length) != 0) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    return PSA_SUCCESS;
}

psa_status_t psa_hash_suspend(psa_hash_operation_t * operation,
                              uint8_t * hash_state,
                              size_t hash_state_size,
                              size_t * hash_state_length)
{
    (void) operation;
    (void) hash_state;
    (void) hash_state_size;
    (void) hash_state_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_hash_resume(psa_hash_operation_t * operation,
                             const uint8_t * hash_state,
                             size_t hash_state_length)
{
    (void) operation;
    (void) hash_state;
    (void) hash_state_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_hash_abort(psa_hash_operation_t * operation)
{
    *operation = psa_hash_operation_init();
    return PSA_SUCCESS;
}

psa_status_t psa_hash_clone(const psa_hash_operation_t * source_operation,
                            psa_hash_operation_t * target_operation)
{
    (void) source_operation;
    (void) target_operation;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_hash_compare(psa_algorithm_t alg,
                              const uint8_t * input,
                              size_t input_length,
                              const uint8_t * hash,
                              size_t hash_length)
{
    psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    status = psa_hash_setup(&operation, alg);
    if (status != PSA_SUCCESS) {
        return status;
    }
    status = psa_hash_update(&operation, input, input_length);
    if (status != PSA_SUCCESS) {
        return status;
    }
    status = psa_hash_verify(&operation, hash, hash_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    return PSA_SUCCESS;
}

psa_status_t psa_hash_compute(psa_algorithm_t alg,
                              const uint8_t * input,
                              size_t input_length,
                              uint8_t * hash,
                              size_t hash_size,
                              size_t * hash_length)
{
    psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    *hash_length = hash_size;
    status = psa_hash_setup(&operation, alg);
    if (status != PSA_SUCCESS) {
        return status;
    }
    status = psa_hash_update(&operation, input, input_length);
    if (status != PSA_SUCCESS) {
        return status;
    }
    status = psa_hash_finish(&operation, hash, hash_size, hash_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    return PSA_SUCCESS;
}

/* Key Management */

psa_status_t psa_copy_key_material_into_slot( psa_key_slot_t *slot, const uint8_t *data, size_t data_length)
{
    if (data_length > PSA_MAX_KEY_LENGTH) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    memcpy(slot->key.data, data, data_length);
    return PSA_SUCCESS;
}

static psa_status_t psa_validate_key_policy(const psa_key_policy_t *policy)
{
    if ((policy->usage & ~( PSA_KEY_USAGE_EXPORT |
                            PSA_KEY_USAGE_COPY |
                            PSA_KEY_USAGE_ENCRYPT |
                            PSA_KEY_USAGE_DECRYPT |
                            PSA_KEY_USAGE_SIGN_MESSAGE |
                            PSA_KEY_USAGE_VERIFY_MESSAGE |
                            PSA_KEY_USAGE_SIGN_HASH |
                            PSA_KEY_USAGE_VERIFY_HASH |
                            PSA_KEY_USAGE_DERIVE ) ) != 0 ) {
        return( PSA_ERROR_INVALID_ARGUMENT );
    }

    return( PSA_SUCCESS );
}

static psa_status_t psa_validate_key_attributes(const psa_key_attributes_t *attributes, psa_se_drv_data_t **p_drv)
{
    psa_status_t status = PSA_ERROR_INVALID_ARGUMENT;
    psa_key_lifetime_t lifetime = psa_get_key_lifetime(attributes);
    psa_key_id_t key = psa_get_key_id(attributes);

    status = psa_validate_key_location(lifetime, p_drv);
    if (status != PSA_SUCCESS) {
        printf("Line: %d, status: %ld\n", __LINE__, status);
        return status;
    }

    status = psa_validate_key_persistence(lifetime);
    if (status != PSA_SUCCESS) {
        printf("Line: %d, status: %ld\n", __LINE__, status);
        return status;
    }

    if (PSA_KEY_LIFETIME_IS_VOLATILE(lifetime)) {
        if (key != 0) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }
    else {
        if (!psa_is_valid_key_id(key, 0)) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }

    status = psa_validate_key_policy(&attributes->policy);
    if (status != PSA_SUCCESS) {
        printf("Line: %d, status: %ld\n", __LINE__, status);
        return status;
    }

    if (psa_get_key_bits(attributes) > PSA_MAX_KEY_BITS) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    return PSA_SUCCESS;
}

static psa_status_t psa_start_key_creation(psa_key_creation_method_t method, const psa_key_attributes_t *attributes, psa_key_slot_t **p_slot, psa_se_drv_data_t **p_drv)
{
    psa_status_t status;
    psa_key_id_t key_id;
    psa_key_slot_t *slot;

    *p_drv = NULL;

    status = psa_validate_key_attributes(attributes, p_drv);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = psa_get_empty_key_slot(&key_id, p_slot);
    if (status != PSA_SUCCESS) {
        return status;
    }
    slot = *p_slot;
    slot->attr = *attributes;

    if (PSA_KEY_LIFETIME_IS_VOLATILE(slot->attr.lifetime)) {
        slot->attr.id = key_id;
    }

#if IS_ACTIVE(CONFIG_PSA_CRYPTO_SECURE_ELEMENT)
    if (*p_drv != NULL) {
        psa_key_slot_number_t slot_number;
        status = psa_find_free_se_slot(attributes, method, *p_drv, &slot_number);
        if (status != PSA_SUCCESS) {
            printf("Line: %d, status: %ld\n", __LINE__, status);
            return status;
        }
        /* TODO: Start transaction for persistent key storage */
        status = psa_copy_key_material_into_slot(slot, (uint8_t*)(&slot_number), sizeof(slot_number));
        if (status != PSA_SUCCESS) {
            return status;
        }
    }
    if (*p_drv == NULL && method == PSA_KEY_CREATION_REGISTER) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
#endif /* CONFIG_PSA_CRYPTO_SECURE_ELEMENT */

    (void) method;
    return PSA_SUCCESS;
}

static psa_status_t psa_finish_key_creation(psa_key_slot_t *slot, psa_se_drv_data_t *driver, psa_key_id_t *key)
{
    psa_status_t status = PSA_SUCCESS;

    /* TODO: Finish persistent key storage */
    /* TODO: Finish SE key storage with transaction */

    if (status == PSA_SUCCESS) {
        *key = slot->attr.id;
        status = psa_unlock_key_slot(slot);
        if (status != PSA_SUCCESS) {
            *key = 0;
        }
    }
    else {
        (void) slot;
    }

    (void) driver;
    return status;
}

static void psa_fail_key_creation(psa_key_slot_t *slot, psa_se_drv_data_t *driver)
{
    (void) driver;
    if (slot == NULL) {
        return;
    }
    /* TODO: Destroy key in secure element (see mbedtls code) */
    /* TODO: Secure Element stop transaction */
    psa_wipe_key_slot(slot);
}

psa_status_t psa_import_key(const psa_key_attributes_t * attributes,
                            const uint8_t * data,
                            size_t data_length,
                            psa_key_id_t * key)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_slot_t *slot = NULL;
    psa_se_drv_data_t *driver = NULL;
    size_t bits;
    *key = 0;

    /* Find empty slot */
    status = psa_start_key_creation(PSA_KEY_CREATION_IMPORT, attributes, &slot, &driver);

    if (status != PSA_SUCCESS) {
        psa_fail_key_creation(slot, driver);
        return status;
    }

    bits = slot->attr.bits;
    status = psa_driver_wrapper_import_key(attributes, data, data_length, slot->key.data, slot->key.bytes, &slot->key.bytes, &bits);

    if (status != PSA_SUCCESS) {
        psa_fail_key_creation(slot, driver);
        return status;
    }

    if (slot->attr.bits == 0) {
        slot->attr.bits = (psa_key_bits_t) bits;
    }
    else if (bits != slot->attr.bits) {
        psa_fail_key_creation(slot, driver);
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    status = psa_finish_key_creation(slot, driver, key);

    if (status != PSA_SUCCESS) {
        psa_fail_key_creation(slot, driver);
    }

    return status;
}

psa_status_t psa_key_derivation_abort(psa_key_derivation_operation_t * operation)
{
    (void) operation;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_key_derivation_get_capacity(const psa_key_derivation_operation_t * operation,
                                             size_t * capacity)
{
    (void) operation;
    (void) capacity;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_key_derivation_input_bytes(psa_key_derivation_operation_t * operation,
                                            psa_key_derivation_step_t step,
                                            const uint8_t * data,
                                            size_t data_length)
{
    (void) operation;
    (void) step;
    (void) data;
    (void) data_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_key_derivation_input_key(psa_key_derivation_operation_t * operation,
                                          psa_key_derivation_step_t step,
                                          psa_key_id_t key)
{
    (void) operation;
    (void) step;
    (void) key;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_key_derivation_key_agreement(psa_key_derivation_operation_t * operation,
                                              psa_key_derivation_step_t step,
                                              psa_key_id_t private_key,
                                              const uint8_t * peer_key,
                                              size_t peer_key_length)
{
    (void) operation;
    (void) step;
    (void) private_key;
    (void) peer_key;
    (void) peer_key_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_key_derivation_operation_t psa_key_derivation_operation_init(void)
{
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_key_derivation_output_bytes(psa_key_derivation_operation_t * operation,
                                             uint8_t * output,
                                             size_t output_length)
{
    (void) operation;
    (void) output;
    (void) output_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_key_derivation_output_key(const psa_key_attributes_t * attributes,
                                           psa_key_derivation_operation_t * operation,
                                           psa_key_id_t * key)
{
    (void) attributes;
    (void) operation;
    (void) key;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_key_derivation_set_capacity(psa_key_derivation_operation_t * operation,
                                             size_t capacity)
{
    (void) operation;
    (void) capacity;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_key_derivation_setup(psa_key_derivation_operation_t * operation,
                                      psa_algorithm_t alg)
{
    (void) operation;
    (void) alg;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_mac_abort(psa_mac_operation_t * operation)
{
    (void) operation;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_mac_compute(psa_key_id_t key,
                             psa_algorithm_t alg,
                             const uint8_t * input,
                             size_t input_length,
                             uint8_t * mac,
                             size_t mac_size,
                             size_t * mac_length)
{
    (void) key;
    (void) alg;
    (void) input;
    (void) input_length;
    (void) mac;
    (void) mac_size;
    (void) mac_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_mac_operation_t psa_mac_operation_init(void)
{
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_mac_sign_finish(psa_mac_operation_t * operation,
                                 uint8_t * mac,
                                 size_t mac_size,
                                 size_t * mac_length)
{
    (void) operation;
    (void) mac;
    (void) mac_size;
    (void) mac_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_mac_sign_setup(psa_mac_operation_t * operation,
                                psa_key_id_t key,
                                psa_algorithm_t alg)
{
    (void) operation;
    (void) key;
    (void) alg;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_mac_update(psa_mac_operation_t * operation,
                            const uint8_t * input,
                            size_t input_length)
{
    (void) operation;
    (void) input;
    (void) input_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_mac_verify(psa_key_id_t key,
                            psa_algorithm_t alg,
                            const uint8_t * input,
                            size_t input_length,
                            const uint8_t * mac,
                            size_t mac_length)
{
    (void) key;
    (void) alg;
    (void) input;
    (void) input_length;
    (void) mac;
    (void) mac_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_mac_verify_finish(psa_mac_operation_t * operation,
                                   const uint8_t * mac,
                                   size_t mac_length)
{
    (void) operation;
    (void) mac;
    (void) mac_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_mac_verify_setup(psa_mac_operation_t * operation,
                                  psa_key_id_t key,
                                  psa_algorithm_t alg)
{
    (void) operation;
    (void) key;
    (void) alg;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_purge_key(psa_key_id_t key)
{
    (void) key;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_raw_key_agreement(psa_algorithm_t alg,
                                   psa_key_id_t private_key,
                                   const uint8_t * peer_key,
                                   size_t peer_key_length,
                                   uint8_t * output,
                                   size_t output_size,
                                   size_t * output_length)
{
    (void) alg;
    (void) private_key;
    (void) peer_key;
    (void) peer_key_length;
    (void) output;
    (void) output_size;
    (void) output_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

void psa_reset_key_attributes(psa_key_attributes_t * attributes)
{
    *attributes = psa_key_attributes_init();
}

void psa_set_key_algorithm(psa_key_attributes_t * attributes,
                           psa_algorithm_t alg)
{
    attributes->policy.alg = alg;
}

void psa_set_key_bits(psa_key_attributes_t * attributes,
                      size_t bits)
{
    attributes->bits = bits;
}

void psa_set_key_id(psa_key_attributes_t * attributes,
                    psa_key_id_t id)
{
    attributes->id = id;
}

void psa_set_key_lifetime(psa_key_attributes_t * attributes,
                          psa_key_lifetime_t lifetime)
{
    attributes->lifetime = lifetime;
}

void psa_set_key_type(psa_key_attributes_t * attributes,
                      psa_key_type_t type)
{
    attributes->type = type;
}

void psa_set_key_usage_flags(psa_key_attributes_t * attributes,
                             psa_key_usage_t usage_flags)
{
    attributes->policy.usage = usage_flags;
}

psa_status_t psa_sign_hash(psa_key_id_t key,
                           psa_algorithm_t alg,
                           const uint8_t * hash,
                           size_t hash_length,
                           uint8_t * signature,
                           size_t signature_size,
                           size_t * signature_length)
{
    (void) key;
    (void) alg;
    (void) hash;
    (void) hash_length;
    (void) signature;
    (void) signature_size;
    (void) signature_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_sign_message(psa_key_id_t key,
                              psa_algorithm_t alg,
                              const uint8_t * input,
                              size_t input_length,
                              uint8_t * signature,
                              size_t signature_size,
                              size_t * signature_length)
{
    (void) key;
    (void) alg;
    (void) input;
    (void) input_length;
    (void) signature;
    (void) signature_size;
    (void) signature_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_verify_hash(psa_key_id_t key,
                             psa_algorithm_t alg,
                             const uint8_t * hash,
                             size_t hash_length,
                             const uint8_t * signature,
                             size_t signature_length)
{
    (void) key;
    (void) alg;
    (void) hash;
    (void) hash_length;
    (void) signature;
    (void) signature_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_verify_message(psa_key_id_t key,
                                psa_algorithm_t alg,
                                const uint8_t * input,
                                size_t input_length,
                                const uint8_t * signature,
                                size_t signature_length)
{
    (void) key;
    (void) alg;
    (void) input;
    (void) input_length;
    (void) signature;
    (void) signature_length;
    return PSA_ERROR_NOT_SUPPORTED;
}
