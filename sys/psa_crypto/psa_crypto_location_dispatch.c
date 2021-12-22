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
 * @brief       Wrapper to combine several available cryptographic backends.
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#include <stdio.h>
#include "kernel_defines.h"
#include "psa/crypto.h"
#include "include/psa_builtin_key_manager.h"
#include "include/psa_crypto_algorithm_dispatch.h"
#include "include/psa_crypto_slot_management.h"
#include "include/psa_crypto_se_management.h"
#include "include/psa_crypto_se_driver.h"

psa_status_t psa_location_dispatch_export_public_key(  const psa_key_attributes_t *attributes,
                                                    uint8_t *key_buffer,
                                                    size_t key_buffer_size,
                                                    uint8_t * data,
                                                    size_t data_size,
                                                    size_t * data_length)
{
    /* Currently only direct copying of the key from local memory is supported */
    return psa_builtin_export_public_key(attributes, key_buffer, key_buffer_size, data, data_size, data_length);
}

psa_status_t psa_location_dispatch_generate_key(   const psa_key_attributes_t *attributes,
                                                uint8_t *key_buffer, size_t key_buffer_size,
                                                size_t *key_buffer_length, uint8_t *pubkey_buffer, size_t pubkey_buffer_size, size_t *pubkey_buffer_length)
{
#if IS_ACTIVE(CONFIG_PSA_SECURE_ELEMENT)
    const psa_drv_se_t *drv;
    psa_drv_se_context_t *drv_context;

    if (psa_get_se_driver(attributes->lifetime, &drv, &drv_context)) {
        if (drv->key_management == NULL || drv->key_management->p_generate == NULL) {
            return PSA_ERROR_NOT_SUPPORTED;
        }

        return drv->key_management->p_generate(drv_context, *((psa_key_slot_number_t*)key_buffer), attributes, pubkey_buffer, pubkey_buffer_size, pubkey_buffer_length);
    }
#endif /* CONFIG_PSA_SECURE_ELEMENT */

    return psa_algorithm_dispatch_generate_key(attributes, key_buffer, key_buffer_size, key_buffer_length, pubkey_buffer, pubkey_buffer_size, pubkey_buffer_length);
}

psa_status_t psa_location_dispatch_import_key( const psa_key_attributes_t *attributes,
                                            const uint8_t *data, size_t data_length,
                                            uint8_t *key_buffer, size_t key_buffer_size,
                                            size_t *key_buffer_length, size_t *bits)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime);

#if IS_ACTIVE(CONFIG_PSA_SECURE_ELEMENT)
    const psa_drv_se_t *drv;
    psa_drv_se_context_t *drv_context;

    if (psa_get_se_driver(attributes->lifetime, &drv, &drv_context)) {
        if (drv->key_management == NULL || drv->key_management->p_import == NULL) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
        *bits = 0;
        status = drv->key_management->p_import(drv_context, *((psa_key_slot_number_t*)key_buffer), attributes, data, data_length, bits);
        if (status != PSA_SUCCESS) {
            return status;
        }
        if (*bits > PSA_MAX_KEY_BITS) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
        return PSA_SUCCESS;
    }
#endif /* CONFIG_PSA_SECURE_ELEMENT */

    switch(location) {
        case PSA_KEY_LOCATION_LOCAL_STORAGE:
            return psa_builtin_import_key(attributes, data, data_length, key_buffer, key_buffer_size, key_buffer_length, bits);
        default:
            (void) status;
            return PSA_ERROR_NOT_SUPPORTED;
    }
}

psa_status_t psa_location_dispatch_cipher_encrypt_setup(   psa_cipher_operation_t *operation,
                                                    const psa_key_attributes_t *attributes,
                                                    const uint8_t *key_buffer,
                                                    size_t key_buffer_size,
                                                    psa_algorithm_t alg)
{
#if IS_ACTIVE(CONFIG_PSA_SECURE_ELEMENT)
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime);
    if (location != PSA_KEY_LOCATION_LOCAL_STORAGE) {
        const psa_drv_se_t *drv;
        psa_drv_se_context_t *drv_context;
        psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

        if (psa_get_se_driver(attributes->lifetime, &drv, &drv_context)) {
            if (drv->cipher == NULL || drv->cipher->p_setup == NULL) {
                return PSA_ERROR_NOT_SUPPORTED;
            }
            status = drv->cipher->p_setup(drv_context, &operation->ctx, *((psa_key_slot_number_t*) key_buffer), attributes->policy.alg, PSA_CRYPTO_DRIVER_ENCRYPT);
            if (status != PSA_SUCCESS) {
                return status;
            }
            return PSA_SUCCESS;
        }
    }
#endif /* CONFIG_PSA_SECURE_ELEMENT */
    (void) operation;
    (void) attributes;
    (void) key_buffer;
    (void) key_buffer_size;
    (void) alg;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_location_dispatch_cipher_decrypt_setup(psa_cipher_operation_t *operation,
                                                    const psa_key_attributes_t *attributes,
                                                    const uint8_t *key_buffer,
                                                    size_t key_buffer_size,
                                                    psa_algorithm_t alg)
{
    (void) operation;
    (void) attributes;
    (void) key_buffer;
    (void) key_buffer_size;
    (void) alg;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_location_dispatch_cipher_encrypt( psa_key_slot_t *slot,
                                                psa_algorithm_t alg,
                                                const uint8_t * input,
                                                size_t input_length,
                                                uint8_t * output,
                                                size_t output_size,
                                                size_t * output_length)
{
#if IS_ACTIVE(CONFIG_PSA_SECURE_ELEMENT)
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    const psa_drv_se_t *drv;
    psa_drv_se_context_t *drv_context;

    if (psa_get_se_driver(slot->attr.lifetime, &drv, &drv_context)) {
        if (alg != PSA_ALG_ECB_NO_PADDING) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
        if (drv->cipher == NULL || drv->cipher->p_ecb == NULL) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
        status = drv->cipher->p_ecb(drv_context, *((psa_key_slot_number_t *) slot->key.data), alg, PSA_CRYPTO_DRIVER_ENCRYPT, input, input_length, output, output_size);
        if (status != PSA_SUCCESS) {
            return status;
        }
        return PSA_SUCCESS;
    }
#endif /* CONFIG_PSA_SECURE_ELEMENT */

    return psa_algorithm_dispatch_cipher_encrypt(slot, alg, input, input_length, output, output_size, output_length);
}

psa_status_t psa_location_dispatch_sign_hash(  const psa_key_attributes_t *attributes,
                                            psa_algorithm_t alg,
                                            const uint8_t *key_buffer,
                                            size_t key_buffer_size,
                                            const uint8_t * hash,
                                            size_t hash_length,
                                            uint8_t * signature,
                                            size_t signature_size,
                                            size_t * signature_length)
{
#if IS_ACTIVE(CONFIG_PSA_SECURE_ELEMENT)
    const psa_drv_se_t *drv;
    psa_drv_se_context_t *drv_context;

    if (psa_get_se_driver(attributes->lifetime, &drv, &drv_context)) {
        if (drv->asymmetric == NULL || drv->asymmetric->p_sign == NULL) {
            return PSA_ERROR_NOT_SUPPORTED;
        }

        return drv->asymmetric->p_sign(drv_context, *((psa_key_slot_number_t*)key_buffer), alg, hash, hash_length, signature, signature_size, signature_length);
    }
#endif /* CONFIG_PSA_SECURE_ELEMENT */

    return psa_algorithm_dispatch_sign_hash(attributes, alg, key_buffer, key_buffer_size, hash, hash_length, signature, signature_size, signature_length);
}

psa_status_t psa_location_dispatch_verify_hash(const psa_key_attributes_t *attributes,
                                            psa_algorithm_t alg,
                                            const uint8_t *key_buffer,
                                            size_t key_buffer_size,
                                            const uint8_t * hash,
                                            size_t hash_length,
                                            const uint8_t * signature,
                                            size_t signature_length)
{
#if IS_ACTIVE(CONFIG_PSA_SECURE_ELEMENT)
    const psa_drv_se_t *drv;
    psa_drv_se_context_t *drv_context;

    if (psa_get_se_driver(attributes->lifetime, &drv, &drv_context)) {
        if (drv->asymmetric == NULL || drv->asymmetric->p_verify == NULL) {
            return PSA_ERROR_NOT_SUPPORTED;
        }

        if (PSA_KEY_TYPE_IS_ECC(attributes->type)) {
            return drv->asymmetric->p_verify(drv_context, key_buffer, alg, hash, hash_length, signature, signature_length);
        }
    }
#endif /* CONFIG_PSA_SECURE_ELEMENT */

    return psa_algorithm_dispatch_verify_hash(attributes, alg, key_buffer, key_buffer_size, hash, hash_length, signature, signature_length);
}

psa_status_t psa_location_dispatch_generate_random(uint8_t * output,
                                                size_t output_size)
{
    return psa_builtin_generate_random(output, output_size);
}
