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
 * @brief       Size definitions for PSA Crypto
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#ifndef PSA_CRYPTO_SIZES_H
#define PSA_CRYPTO_SIZES_H

#include "kernel_defines.h"
#include "crypto_values.h"

#define PSA_BITS_TO_BYTES(bits) (((bits) + 7) / 8)
#define PSA_BYTES_TO_BITS(bytes) ((bytes) * 8)

#define PSA_HASH_LENGTH(alg)                                      \
    (                                                           \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_MD2 ? 16 :            \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_MD4 ? 16 :            \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_MD5 ? 16 :            \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_RIPEMD160 ? 20 :      \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_1 ? 20 :          \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_224 ? 28 :        \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_256 ? 32 :        \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_384 ? 48 :        \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_512 ? 64 :        \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_512_224 ? 28 :    \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA_512_256 ? 32 :    \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA3_224 ? 28 :       \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA3_256 ? 32 :       \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA3_384 ? 48 :       \
        PSA_ALG_HMAC_GET_HASH(alg) == PSA_ALG_SHA3_512 ? 64 :       \
        0)

/* Maximum size of the export encoding of an ECC public key.
 *
 * The representation of an ECC public key is:
 *      - The byte 0x04;
 *      - `x_P` as a `ceiling(m/8)`-byte string, big-endian;
 *      - `y_P` as a `ceiling(m/8)`-byte string, big-endian;
 *      - where m is the bit size associated with the curve.
 *
 * - 1 byte + 2 * point size.
 */
#define PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(key_bits)        \
    (2 * PSA_BITS_TO_BYTES(key_bits) + 1)

/** Sufficient output buffer size for psa_export_public_key().
 *
 * This macro returns a compile-time constant if its arguments are
 * compile-time constants.
 *
 * @warning This macro may evaluate its arguments multiple times or
 *          zero times, so you should not pass arguments that contain
 *          side effects.
 *
 * The following code illustrates how to allocate enough memory to export
 * a public key by querying the key type and size at runtime.
 * @code{c}
 * psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
 * psa_status_t status;
 * status = psa_get_key_attributes(key, &attributes);
 * if (status != PSA_SUCCESS) handle_error(...);
 * psa_key_type_t key_type = psa_get_key_type(&attributes);
 * size_t key_bits = psa_get_key_bits(&attributes);
 * size_t buffer_size = PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(key_type, key_bits);
 * psa_reset_key_attributes(&attributes);
 * uint8_t *buffer = malloc(buffer_size);
 * if (buffer == NULL) handle_error(...);
 * size_t buffer_length;
 * status = psa_export_public_key(key, buffer, buffer_size, &buffer_length);
 * if (status != PSA_SUCCESS) handle_error(...);
 * @endcode
 *
 * @param key_type      A public key or key pair key type.
 * @param key_bits      The size of the key in bits.
 *
 * @return              If the parameters are valid and supported, return
 *                      a buffer size in bytes that guarantees that
 *                      psa_export_public_key() will not fail with
 *                      #PSA_ERROR_BUFFER_TOO_SMALL.
 *                      If the parameters are a valid combination that is not
 *                      supported, return either a sensible size or 0.
 *                      If the parameters are not valid,
 *                      the return value is unspecified.
 *
 *                      If the parameters are valid and supported,
 *                      return the same result as
 *                      #PSA_EXPORT_KEY_OUTPUT_SIZE(
 *                          \p #PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(\p key_type),
 *                          \p key_bits).
 */
#define PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(key_type, key_bits)                           \
    (PSA_KEY_TYPE_IS_ECC(key_type) ? PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(key_bits) : \
     0)

/**
 * Sufficient buffer size for exporting any asymmetric public key.
 *
 * This macro expands to a compile-time constant integer. This value is
 * a sufficient buffer size when calling psa_export_key() or
 * psa_export_public_key() to export any asymmetric public key,
 * regardless of the exact key type and key size.
 *
 * See also #PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(\p key_type, \p key_bits).
 */
#define PSA_EXPORT_PUBLIC_KEY_MAX_SIZE \
        (PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(PSA_VENDOR_ECC_MAX_CURVE_BITS))



#if IS_ACTIVE(CONFIG_PSA_ECC_P256)
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 256
#elif IS_ACTIVE(CONFIG_PSA_ECC_P192)
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 192
#else
#define PSA_VENDOR_ECC_MAX_CURVE_BITS 0
#endif

/* Implementations that have its own generic ECC key type define these sizes themselves. For other implementations the private key is the size of the curve in bytes and the public key type is the */
#if !IS_ACTIVE(CONFIG_PSA_HAS_OWN_ECC_KEY_TYPE)
#define PSA_MAX_ECC_PRIV_KEY_SIZE   (PSA_BITS_TO_BYTES(PSA_VENDOR_ECC_MAX_CURVE_BITS))
#define PSA_MAX_ECC_PUB_KEY_SIZE    (PSA_MAX_ECC_PRIV_KEY_SIZE * 2)
#endif

/**
 * Define maximum key data sizes for initial key buffer declarations.
 *
 * When no key based algorithms are used, PSA_MAX_KEY_DATA_SIZE is 0.
 * When using symmetric ciphers, PSA_MAX_KEY_DATA_SIZE is the size
 * of the largest cipher key used.
 *
 * When using asymmetric ciphers, PSA_MAX_KEY_DATA_SIZE is the size
 * of the largest asymmetric key pair combination used.
 */
#if IS_ACTIVE(CONFIG_PSA_ECC)
#define PSA_MAX_KEY_DATA_SIZE  ((PSA_MAX_ECC_PRIV_KEY_SIZE + PSA_MAX_ECC_PUB_KEY_SIZE + sizeof(size_t)))
#elif IS_ACTIVE(CONFIG_PSA_CIPHER_AES_KEY_SIZE_256)
#define PSA_MAX_KEY_DATA_SIZE  (32)
#elif IS_ACTIVE(CONFIG_PSA_CIPHER_AES_KEY_SIZE_192)
#define PSA_MAX_KEY_DATA_SIZE  (24)
#elif IS_ACTIVE(CONFIG_PSA_CIPHER_AES_KEY_SIZE_128)
#define PSA_MAX_KEY_DATA_SIZE  (16)
#else
#define PSA_MAX_KEY_DATA_SIZE  (0)
#endif

/**
 * @brief ECDSA signature size for a given curve bit size
 *
 * @param curve_bits    Curve size in bits.
 * @return              Signature size in bytes.
 *
 * @note This macro returns a compile-time constant if its argument is one.
 */
#define PSA_ECDSA_SIGNATURE_SIZE(curve_bits)    \
    (PSA_BITS_TO_BYTES(curve_bits) * 2)

/**
 * Sufficient signature buffer size for psa_sign_hash().
 *
 * This macro returns a sufficient buffer size for a signature using a key
 * of the specified type and size, with the specified algorithm.
 * Note that the actual size of the signature may be smaller
 * (some algorithms produce a variable-size signature).
 *
 * @warning This function may call its arguments multiple times or
 *          zero times, so you should not pass arguments that contain
 *          side effects.
 *
 * @param key_type  An asymmetric key type (this may indifferently be a
 *                  key pair type or a public key type).
 * @param key_bits  The size of the key in bits.
 * @param alg       The signature algorithm.
 *
 * @return If the parameters are valid and supported, return
 *         a buffer size in bytes that guarantees that
 *         psa_sign_hash() will not fail with
 *         #PSA_ERROR_BUFFER_TOO_SMALL.
 *         If the parameters are a valid combination that is not supported,
 *         return either a sensible size or 0.
 *         If the parameters are not valid, the
 *         return value is unspecified.
 */
#define PSA_SIGN_OUTPUT_SIZE(key_type, key_bits, alg)        \
    (PSA_KEY_TYPE_IS_ECC(key_type) ? PSA_ECDSA_SIGNATURE_SIZE(key_bits) : \
     ((void)alg, 0))

#define PSA_CONVERT_KEY_SIZE(key_type, key_bits) \
    (PSA_KEY_TYPE_IS_UNSTRUCTURED(key_type) ? PSA_BITS_TO_BYTES(key_bits) : \
    0)

#endif /* PSA_CRYPTO_SIZES_H */
