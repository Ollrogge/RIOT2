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
#include "include/psa_ecc.h"
#include "include/psa_hashes.h"
#include "include/psa_ciphers.h"
#include "include/psa_crypto_operation_encoder.h"
#include "include/psa_crypto_slot_management.h"


psa_status_t psa_algorithm_dispatch_hash_setup(psa_hash_operation_t * operation,
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
    #if IS_ACTIVE(CONFIG_HASHES_SHA512)
        case PSA_ALG_SHA_512:
            status = psa_hashes_sha512_setup(&operation->ctx.sha512);
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

psa_status_t psa_algorithm_dispatch_hash_update(psa_hash_operation_t * operation,
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
    #if IS_ACTIVE(CONFIG_HASHES_SHA512)
        case PSA_ALG_SHA_512:
            return psa_hashes_sha512_update(&operation->ctx.sha512, input, input_length);
    #endif
        default:
            (void) operation;
            (void) input;
            (void) input_length;
            return PSA_ERROR_NOT_SUPPORTED;
    }
}

psa_status_t psa_algorithm_dispatch_hash_finish(psa_hash_operation_t * operation,
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
    #if IS_ACTIVE(CONFIG_HASHES_SHA512)
        case PSA_ALG_SHA_512:
            return psa_hashes_sha512_finish(&operation->ctx.sha512, hash, hash_size, hash_length);
    #endif
        default:
            (void) operation;
            (void) hash;
            (void) hash_size;
            (void) hash_length;
            return PSA_ERROR_NOT_SUPPORTED;
    }
}

psa_status_t psa_algorithm_dispatch_sign_hash(  const psa_key_attributes_t *attributes,
                                            psa_algorithm_t alg,
                                            const uint8_t *key_buffer,
                                            size_t key_buffer_size,
                                            const uint8_t * hash,
                                            size_t hash_length,
                                            uint8_t * signature,
                                            size_t signature_size,
                                            size_t * signature_length)
{
    psa_asymmetric_keytype_t asym_key = PSA_INVALID_OPERATION;

    if (PSA_KEY_TYPE_IS_ECC_KEY_PAIR(attributes->type)) {
        asym_key = PSA_ENCODE_ECC_KEY_TYPE(attributes->bits, PSA_KEY_TYPE_ECC_GET_CURVE(attributes->type));

        if (asym_key == PSA_INVALID_OPERATION) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }

    switch(asym_key) {
#if IS_ACTIVE(CONFIG_PSA_ECC_P192_DRIVER)
        case PSA_ECC_P192_R1:
            return psa_ecc_p192r1_sign_hash(attributes, alg, key_buffer, key_buffer_size, hash, hash_length, signature, signature_size, signature_length);
#endif
#if IS_ACTIVE(CONFIG_PSA_ECC_P256_DRIVER)
        case PSA_ECC_P256_R1:
            return psa_ecc_p256r1_sign_hash(attributes, alg, key_buffer, key_buffer_size, hash, hash_length, signature, signature_size, signature_length);
#endif
        default:
            (void) alg;
            (void) key_buffer;
            (void) key_buffer_size;
            (void) hash;
            (void) hash_length;
            (void) signature;
            (void) signature_size;
            (void) signature_length;
            return PSA_ERROR_NOT_SUPPORTED;
    }
}

psa_status_t psa_algorithm_dispatch_verify_hash(  const psa_key_attributes_t *attributes,
                                            psa_algorithm_t alg,
                                            const uint8_t *key_buffer,
                                            size_t key_buffer_size,
                                            const uint8_t * hash,
                                            size_t hash_length,
                                            const uint8_t * signature,
                                            size_t signature_length)
{
    psa_asymmetric_keytype_t asym_key = PSA_INVALID_OPERATION;

    if (PSA_KEY_TYPE_IS_ECC(attributes->type)) {
        asym_key = PSA_ENCODE_ECC_KEY_TYPE(attributes->bits, PSA_KEY_TYPE_ECC_GET_CURVE(attributes->type));

        if (asym_key == PSA_INVALID_OPERATION) {
            return PSA_ERROR_INVALID_ARGUMENT;
        }
    }

    switch(asym_key) {
#if IS_ACTIVE(CONFIG_PSA_ECC_P192_DRIVER)
        case PSA_ECC_P192_R1:
            return psa_ecc_p192r1_verify_hash(attributes, alg, key_buffer, key_buffer_size, hash, hash_length, signature, signature_length);
#endif
#if IS_ACTIVE(CONFIG_PSA_ECC_P256_DRIVER)
        case PSA_ECC_P256_R1:
            return psa_ecc_p256r1_verify_hash(attributes, alg, key_buffer, key_buffer_size, hash, hash_length, signature, signature_length);
#endif
        default:
            (void) alg;
            (void) key_buffer;
            (void) key_buffer_size;
            (void) hash;
            (void) hash_length;
            (void) signature;
            (void) signature_length;
            return PSA_ERROR_NOT_SUPPORTED;
    }
}

psa_status_t psa_algorithm_dispatch_generate_key(   const psa_key_attributes_t *attributes,
                                                    uint8_t *key_buffer, size_t key_buffer_size,
                                                    size_t *key_buffer_length, uint8_t *pubkey_buffer, size_t pubkey_buffer_size, size_t *pubkey_buffer_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    /* Only asymmetric key generation needs special key generation algorithms. Unstructured keys can be created by generating random bytes. */
    if (PSA_KEY_TYPE_IS_ASYMMETRIC(attributes->type)) {
        psa_asymmetric_keytype_t asym_key = PSA_INVALID_OPERATION;

        if (PSA_KEY_TYPE_IS_ECC_KEY_PAIR(attributes->type)) {
            asym_key = PSA_ENCODE_ECC_KEY_TYPE(attributes->bits, PSA_KEY_TYPE_ECC_GET_CURVE(attributes->type));

            if (asym_key == PSA_INVALID_OPERATION) {
                return PSA_ERROR_INVALID_ARGUMENT;
            }
        }

        switch(asym_key) {
#if IS_ACTIVE(CONFIG_PSA_ECC_P192_DRIVER)
            case PSA_ECC_P192_R1:
                return psa_generate_ecc_p192r1_key_pair(attributes, key_buffer, pubkey_buffer, key_buffer_length, pubkey_buffer_length);
#endif
#if IS_ACTIVE(CONFIG_PSA_ECC_P256_DRIVER)
            case PSA_ECC_P256_R1:
                return psa_generate_ecc_p256r1_key_pair(attributes, key_buffer, pubkey_buffer, key_buffer_length, pubkey_buffer_length);
#endif
            default:
            (void) status;
            (void) key_buffer;
            (void) key_buffer_size;
            (void) key_buffer_length;
            (void) pubkey_buffer;
            (void) pubkey_buffer_size;
            (void) pubkey_buffer_length;
            return PSA_ERROR_NOT_SUPPORTED;
        }
    }

    return psa_builtin_generate_key(attributes, key_buffer, key_buffer_size, key_buffer_length);
}

psa_status_t psa_algorithm_dispatch_cipher_set_iv(  psa_cipher_operation_t *operation,
                                                const uint8_t *iv,
                                                size_t iv_length);

psa_status_t psa_algorithm_dispatch_cipher_encrypt( psa_key_slot_t *slot,
                                            psa_algorithm_t alg,
                                            const uint8_t * input,
                                            size_t input_length,
                                            uint8_t * output,
                                            size_t output_size,
                                            size_t * output_length)
{
    psa_key_attributes_t * attributes = &slot->attr;
    psa_cipher_op_t op = PSA_ENCODE_CIPHER_OPERATION(alg, attributes->bits, attributes->type);

    if (op == PSA_INVALID_OPERATION) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    switch(op) {
#if IS_ACTIVE(CONFIG_PSA_CIPHER_AES_128)
        case PSA_CBC_NO_PAD_AES_128:
            return psa_cipher_cbc_aes_128_encrypt(attributes, slot->key.data, slot->key.bytes, alg, input, input_length, output, output_size, output_length);
#endif
#if IS_ACTIVE(CONFIG_PSA_CIPHER_AES_192)
        case PSA_CBC_NO_PAD_AES_192:
            return psa_cipher_cbc_aes_192_encrypt(attributes, slot->key.data, slot->key.bytes, alg, input, input_length, output, output_size, output_length);
#endif
#if IS_ACTIVE(CONFIG_PSA_CIPHER_AES_256)
        case PSA_CBC_NO_PAD_AES_256:
            return psa_cipher_cbc_aes_256_encrypt(attributes, slot->key.data, slot->key.bytes, alg, input, input_length, output, output_size, output_length);
#endif
        default:
            (void) input;
            (void) input_length;
            (void) output;
            (void) output_size;
            (void) output_length;
            return PSA_ERROR_NOT_SUPPORTED;
    }
}