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

#include "kernel_defines.h"
#include "psa/crypto.h"
#include "include/psa_hashes.h"
#include "include/psa_software_key_management.h"
#include "include/psa_crypto_se_management.h"
#include "include/psa_crypto_se_driver.h"

psa_status_t psa_dispatcher_hash_setup(psa_hash_operation_t * operation,
                                           psa_algorithm_t alg)
{
    psa_status_t status = PSA_ERROR_NOT_SUPPORTED;

    switch(alg) {
    #if IS_ACTIVE(CONFIG_HASHES_MD5)
        case PSA_ALG_MD5:
            status = psa_hashes_md5_setup(&operation->ctx.md5);
            if (status != PSA_SUCCESS) {
                return status;
            }
            break;
    #endif
    #if IS_ACTIVE(CONFIG_HASHES_SHA1)
        case PSA_ALG_SHA_1:
            status = psa_hashes_sha1_setup(&operation->ctx.sha1);
            if (status != PSA_SUCCESS) {
                return status;
            }
            break;
    #endif
    #if IS_ACTIVE(CONFIG_HASHES_SHA224)
        case PSA_ALG_SHA_224:
            status = psa_hashes_sha224_setup(&operation->ctx.sha224);
            if (status != PSA_SUCCESS) {
                return status;
            }
            break;
    #endif
    #if IS_ACTIVE(CONFIG_HASHES_SHA256)
        case PSA_ALG_SHA_256:
            status = psa_hashes_sha256_setup(&operation->ctx.sha256);
            if (status != PSA_SUCCESS) {
                return status;
            }
            break;
    #endif
        default:
            (void) status;
            (void) operation;
            return PSA_ERROR_NOT_SUPPORTED;
    }

    operation->alg = alg;
    return PSA_SUCCESS;
}

psa_status_t psa_dispatcher_hash_update(psa_hash_operation_t * operation,
                             const uint8_t * input,
                             size_t input_length)
{
    switch(operation->alg) {
    #if IS_ACTIVE(CONFIG_HASHES_MD5)
        case PSA_ALG_MD5:
            return psa_hashes_md5_update(&operation->ctx.md5, input, input_length);
    #endif
    #if IS_ACTIVE(CONFIG_HASHES_SHA1)
        case PSA_ALG_SHA_1:
            return psa_hashes_sha1_update(&operation->ctx.sha1, input, input_length);
    #endif
    #if IS_ACTIVE(CONFIG_HASHES_SHA224)
        case PSA_ALG_SHA_224:
            return psa_hashes_sha224_update(&operation->ctx.sha224, input, input_length);
    #endif
    #if IS_ACTIVE(CONFIG_HASHES_SHA256)
        case PSA_ALG_SHA_256:
            return psa_hashes_sha256_update(&operation->ctx.sha256, input, input_length);
    #endif
        default:
            (void) operation;
            return PSA_ERROR_NOT_SUPPORTED;
    }
}

psa_status_t psa_dispatcher_hash_finish(psa_hash_operation_t * operation,
                             uint8_t * hash,
                             size_t hash_size,
                             size_t * hash_length)
{
    switch(operation->alg) {
    #if IS_ACTIVE(CONFIG_HASHES_MD5)
        case PSA_ALG_MD5:
            return psa_hashes_md5_finish(&operation->ctx.md5, hash, hash_size, hash_length);
    #endif
    #if IS_ACTIVE(CONFIG_HASHES_SHA1)
        case PSA_ALG_SHA_1:
            return psa_hashes_sha1_finish(&operation->ctx.sha1, hash, hash_size, hash_length);
    #endif
    #if IS_ACTIVE(CONFIG_HASHES_SHA224)
        case PSA_ALG_SHA_224:
            return psa_hashes_sha224_finish(&operation->ctx.sha224, hash, hash_size, hash_length);
    #endif
    #if IS_ACTIVE(CONFIG_HASHES_SHA256)
        case PSA_ALG_SHA_256:
            return psa_hashes_sha256_finish(&operation->ctx.sha256, hash, hash_size, hash_length);
    #endif
        default:
            (void) operation;
            return PSA_ERROR_NOT_SUPPORTED;
    }
}

psa_status_t psa_dispatcher_import_key( const psa_key_attributes_t *attributes,
                                            const uint8_t *data, size_t data_length,
                                            uint8_t *key_buffer, size_t key_buffer_size,
                                            size_t *key_buffer_length, size_t *bits)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime);

#if IS_ACTIVE(CONFIG_PSA_CRYPTO_SECURE_ELEMENT)
    const psa_drv_se_t *drv;
    psa_drv_se_context_t *drv_context;

    if (psa_get_se_driver(attributes->lifetime, &drv, &drv_context)) {
        if (drv->key_management == NULL || drv->key_management->p_import == NULL) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
        *bits = PSA_MAX_KEY_BITS + 1;
        status = drv->key_management->p_import(drv_context, *(psa_key_slot_number_t*)key_buffer, attributes, data, data_length, bits);
        if (status != PSA_SUCCESS) {
            return status;
        }
        if (*bits > PSA_MAX_KEY_BITS) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
        return PSA_SUCCESS;
    }
#endif /* CONFIG_PSA_CRYPTO_SECURE_ELEMENT */

    switch(location) {
        case PSA_KEY_LOCATION_LOCAL_STORAGE:
            return psa_software_import_key(attributes, data, data_length, key_buffer, key_buffer_size, key_buffer_length, bits);
        default:
            (void) status;
            return PSA_ERROR_NOT_SUPPORTED;
    }
}

psa_status_t psa_dispatcher_cipher_encrypt_setup(   psa_cipher_operation_t *operation,
                                                        const psa_key_attributes_t *attributes,
                                                        const uint8_t *key_buffer,
                                                        size_t key_buffer_size,
                                                        psa_algorithm_t alg)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime);

#if IS_ACTIVE(CONFIG_PSA_CRYPTO_SECURE_ELEMENT)
    const psa_drv_se_t *drv;
    psa_drv_se_context_t *drv_context;

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
#endif /* CONFIG_PSA_CRYPTO_SECURE_ELEMENT */

    switch(location) {
        case PSA_KEY_LOCATION_LOCAL_STORAGE:
#if IS_ACTIVE(CONFIG_PSA_CIPHER_SOFTWARE_IMPLEMENTATION)
        status = psa_software_cipher_encrypt_setup(&operation->ctx.sw_ctx, attributes, key_buffer, key_buffer_size, alg);
        if (status == PSA_SUCCESS) {
            operation->driver_id = PSA_CRYPTO_BUILTIN_DRIVER_ID;
        }
        if (status != PSA_ERROR_NOT_SUPPORTED) {
            return status;
        }
#endif /* CONFIG_BUILTIN_CIPHER */
        (void) status;
        return PSA_ERROR_NOT_SUPPORTED;
    default:
        (void) operation;
        (void) key_buffer;
        (void) key_buffer_size;
        (void) alg;
        return PSA_ERROR_INVALID_ARGUMENT;
    }
}

psa_status_t psa_dispatcher_cipher_decrypt_setup(   psa_cipher_operation_t *operation,
                                                        const psa_key_attributes_t *attributes,
                                                        const uint8_t *key_buffer,
                                                        size_t key_buffer_size,
                                                        psa_algorithm_t alg)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(attributes->lifetime);

    switch(location) {
        case PSA_KEY_LOCATION_LOCAL_STORAGE:
#if IS_ACTIVE(CONFIG_PSA_CIPHER_SOFTWARE_IMPLEMENTATION)
        status = psa_software_cipher_decrypt_setup(&operation->ctx.sw_ctx, attributes, key_buffer, key_buffer_size, alg);
        if (status == PSA_SUCCESS) {
            operation->driver_id = PSA_CRYPTO_BUILTIN_DRIVER_ID;
        }
        if (status != PSA_ERROR_NOT_SUPPORTED) {
            return status;
        }
#endif /* CONFIG_BUILTIN_CIPHER */
        (void) status;
        return PSA_ERROR_NOT_SUPPORTED;
    default:
        (void) operation;
        (void) key_buffer;
        (void) key_buffer_size;
        (void) alg;
        return PSA_ERROR_INVALID_ARGUMENT;
    }
}

psa_status_t psa_dispatcher_cipher_encrypt( psa_cipher_operation_t *operation,
                                                const psa_key_attributes_t *attributes,
                                                const uint8_t * input,
                                                size_t input_length,
                                                uint8_t * output,
                                                size_t output_size,
                                                size_t * output_length)
{
#if IS_ACTIVE(CONFIG_PSA_CRYPTO_SECURE_ELEMENT)
        psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
        const psa_drv_se_t *drv;
        psa_drv_se_context_t *drv_context;

        if (psa_get_se_driver(attributes->lifetime, &drv, &drv_context)) {
            if (drv->cipher == NULL || drv->cipher->p_ecb == NULL) {
                return PSA_ERROR_NOT_SUPPORTED;
            }
            status = drv->cipher->p_ecb(drv_context, operation->ctx.se_key_slot, attributes->policy.alg, PSA_CRYPTO_DRIVER_ENCRYPT, input, input_length, output, output_size);
            if (status != PSA_SUCCESS) {
                return status;
            }
            return PSA_SUCCESS;
        }
#endif /* CONFIG_PSA_CRYPTO_SECURE_ELEMENT */

    switch(operation->driver_id) {
#if IS_ACTIVE(CONFIG_PSA_CIPHER_SOFTWARE_IMPLEMENTATION)
        case PSA_CRYPTO_BUILTIN_DRIVER_ID:
            return psa_software_cipher_encrypt(operation, input, input_length, output, output_size, output_length);
#endif /* CONFIG_BUILTIN_CIPHER */
        default:
        (void) operation;
        (void) attributes;
        (void) input;
        (void) input_length;
        (void) output;
        (void) output_size;
        (void) output_length;
        return PSA_ERROR_INVALID_ARGUMENT;
    }
}