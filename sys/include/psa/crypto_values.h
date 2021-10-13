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
 * @brief       Value definitions for PSA Crypto.
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#ifndef PSA_CRYPTO_VALUES_H
#define PSA_CRYPTO_VALUES_H

#include "crypto_types.h"

/** Vendor-defined algorithm flag.
 *
 * Algorithms defined by this standard will never have the #PSA_ALG_VENDOR_FLAG
 * bit set. Vendors who define additional algorithms must use an encoding with
 * the #PSA_ALG_VENDOR_FLAG bit set and should respect the bitwise structure
 * used by standard encodings whenever practical.
 */
#define PSA_ALG_VENDOR_FLAG                     ((psa_algorithm_t)0x80000000)

#define PSA_ALG_CATEGORY_MASK                   ((psa_algorithm_t)0x7f000000)
#define PSA_ALG_CATEGORY_HASH                   ((psa_algorithm_t)0x02000000)
#define PSA_ALG_CATEGORY_MAC                    ((psa_algorithm_t)0x03000000)
#define PSA_ALG_CATEGORY_CIPHER                 ((psa_algorithm_t)0x04000000)
#define PSA_ALG_CATEGORY_AEAD                   ((psa_algorithm_t)0x05000000)
#define PSA_ALG_CATEGORY_SIGN                   ((psa_algorithm_t)0x06000000)
#define PSA_ALG_CATEGORY_ASYMMETRIC_ENCRYPTION  ((psa_algorithm_t)0x07000000)
#define PSA_ALG_CATEGORY_KEY_DERIVATION         ((psa_algorithm_t)0x08000000)
#define PSA_ALG_CATEGORY_KEY_AGREEMENT          ((psa_algorithm_t)0x09000000)

#define PSA_AEAD_DECRYPT_OUTPUT_MAX_SIZE(ciphertext_length) \
/* implementation-defined value */
#define PSA_AEAD_DECRYPT_OUTPUT_SIZE(key_type, alg, ciphertext_length) \
/* implementation-defined value */
#define PSA_AEAD_ENCRYPT_OUTPUT_MAX_SIZE(plaintext_length) \
/* implementation-defined value */
#define PSA_AEAD_ENCRYPT_OUTPUT_SIZE(key_type, alg, plaintext_length) \
/* implementation-defined value */
#define PSA_AEAD_FINISH_OUTPUT_MAX_SIZE /* implementation-defined value */
#define PSA_AEAD_FINISH_OUTPUT_SIZE(key_type, alg) \
/* implementation-defined value */
#define PSA_AEAD_NONCE_LENGTH(key_type, alg) /* implementation-defined value */
#define PSA_AEAD_NONCE_MAX_SIZE /* implementation-defined value */
#define PSA_AEAD_OPERATION_INIT /* implementation-defined value */
#define PSA_AEAD_TAG_LENGTH(key_type, key_bits, alg) \
/* implementation-defined value */
#define PSA_AEAD_TAG_MAX_SIZE /* implementation-defined value */
#define PSA_AEAD_UPDATE_OUTPUT_MAX_SIZE(input_length) \
/* implementation-defined value */
#define PSA_AEAD_UPDATE_OUTPUT_SIZE(key_type, alg, input_length) \
/* implementation-defined value */
#define PSA_AEAD_VERIFY_OUTPUT_MAX_SIZE /* implementation-defined value */
#define PSA_AEAD_VERIFY_OUTPUT_SIZE(key_type, alg) \
/* implementation-defined value */
#define PSA_ALG_AEAD_WITH_DEFAULT_LENGTH_TAG(aead_alg) \
/* specification-defined value */
#define PSA_ALG_AEAD_WITH_SHORTENED_TAG(aead_alg, tag_length) \
/* specification-defined value */

#define PSA_ALG_GET_HASH(alg) /* specification-defined value */
#define PSA_ALG_HKDF(hash_alg) /* specification-defined value */
#define PSA_ALG_HMAC(hash_alg) /* specification-defined value */
#define PSA_ALG_IS_AEAD(alg) /* specification-defined value */
#define PSA_ALG_IS_AEAD_ON_BLOCK_CIPHER(alg) /* specification-defined value */
#define PSA_ALG_IS_ASYMMETRIC_ENCRYPTION(alg) /* specification-defined value */
#define PSA_ALG_IS_BLOCK_CIPHER_MAC(alg) /* specification-defined value */

/** Whether the specified algorithm is a symmetric cipher algorithm.
 *
 * \param alg An algorithm identifier (value of type #psa_algorithm_t).
 *
 * \return 1 if \p alg is a symmetric cipher algorithm, 0 otherwise.
 *         This macro may return either 0 or 1 if \p alg is not a supported
 *         algorithm identifier.
 */
#define PSA_ALG_IS_CIPHER(alg)                                          \
    (((alg) & PSA_ALG_CATEGORY_MASK) == PSA_ALG_CATEGORY_CIPHER)

#define PSA_ALG_IS_DETERMINISTIC_ECDSA(alg) /* specification-defined value */
#define PSA_ALG_IS_ECDH(alg) /* specification-defined value */

#define PSA_ALG_IS_ECDSA(alg) \
    (((alg) & PSA_ALG_CATEGORY_MASK) == PSA_ALG_CATEGORY_SIGN)

#define PSA_ALG_IS_FFDH(alg) /* specification-defined value */

#define PSA_ALG_IS_HASH(alg) \
    (((alg) & PSA_ALG_CATEGORY_MASK) == PSA_ALG_CATEGORY_HASH)

#define PSA_ALG_HMAC_GET_HASH(hmac_alg)                             \
    (PSA_ALG_CATEGORY_HASH | ((hmac_alg) & PSA_ALG_HASH_MASK))

#define PSA_ALG_IS_HASH_AND_SIGN(alg) /* specification-defined value */
#define PSA_ALG_IS_HKDF(alg) /* specification-defined value */
#define PSA_ALG_IS_HMAC(alg) /* specification-defined value */
#define PSA_ALG_IS_KEY_AGREEMENT(alg) /* specification-defined value */
#define PSA_ALG_IS_KEY_DERIVATION(alg) /* specification-defined value */
#define PSA_ALG_IS_MAC(alg) /* specification-defined value */
#define PSA_ALG_IS_RANDOMIZED_ECDSA(alg) /* specification-defined value */
#define PSA_ALG_IS_RAW_KEY_AGREEMENT(alg) /* specification-defined value */
#define PSA_ALG_IS_RSA_OAEP(alg) /* specification-defined value */
#define PSA_ALG_IS_RSA_PKCS1V15_SIGN(alg) /* specification-defined value */
#define PSA_ALG_IS_RSA_PSS(alg) /* specification-defined value */
#define PSA_ALG_IS_SIGN(alg) /* specification-defined value */
#define PSA_ALG_IS_SIGN_HASH(alg) /* specification-defined value */
#define PSA_ALG_IS_SIGN_MESSAGE(alg) /* specification-defined value */
#define PSA_ALG_IS_STREAM_CIPHER(alg) /* specification-defined value */
#define PSA_ALG_IS_TLS12_PRF(alg) /* specification-defined value */
#define PSA_ALG_IS_TLS12_PSK_TO_MS(alg) /* specification-defined value */
#define PSA_ALG_IS_WILDCARD(alg) /* specification-defined value */

#define PSA_ALG_KEY_AGREEMENT(ka_alg, kdf_alg) \
/* specification-defined value */
#define PSA_ALG_KEY_AGREEMENT_GET_BASE(alg) /* specification-defined value */
#define PSA_ALG_KEY_AGREEMENT_GET_KDF(alg) /* specification-defined value */

#define PSA_ALG_HASH_MASK   ((psa_algorithm_t)0x000000ff)

#define PSA_ALG_CBC_MAC     ((psa_algorithm_t)0x03c00100)
#define PSA_ALG_CMAC        ((psa_algorithm_t)0x03c00200)

#define PSA_ALG_CBC_NO_PADDING  ((psa_algorithm_t)0x04404000)
#define PSA_ALG_CBC_PKCS7       ((psa_algorithm_t)0x04404100)
#define PSA_ALG_ECB_NO_PADDING  ((psa_algorithm_t)0x04404400)
#define PSA_ALG_XTS             ((psa_algorithm_t)0x0440ff00)
#define PSA_ALG_CTR             ((psa_algorithm_t)0x04c01000)
#define PSA_ALG_CFB             ((psa_algorithm_t)0x04c01100)
#define PSA_ALG_OFB             ((psa_algorithm_t)0x04c01200)
#define PSA_ALG_STREAM_CIPHER   ((psa_algorithm_t)0x04800100)

#define PSA_ALG_CHACHA20_POLY1305   ((psa_algorithm_t)0x05100500)
#define PSA_ALG_CCM                 ((psa_algorithm_t)0x05500100)
#define PSA_ALG_GCM                 ((psa_algorithm_t)0x05500200)

#define PSA_ALG_RSA_PKCS1V15_SIGN_RAW   ((psa_algorithm_t) 0x06000200)

#define PSA_ALG_ECDSA_BASE      ((psa_algorithm_t) 0x06000600)

/** ECDSA signature with hashing.
 *
 * This is the ECDSA signature scheme defined by ANSI X9.62,
 * with a random per-message secret number (*k*).
 *
 * The representation of the signature as a byte string consists of
 * the concatentation of the signature values *r* and *s*. Each of
 * *r* and *s* is encoded as an *N*-octet string, where *N* is the length
 * of the base point of the curve in octets. Each value is represented
 * in big-endian order (most significant octet first).
 *
 * \param hash_alg      A hash algorithm (\c PSA_ALG_XXX value such that
 *                      #PSA_ALG_IS_HASH(\p hash_alg) is true).
 *                      This includes #PSA_ALG_ANY_HASH
 *                      when specifying the algorithm in a usage policy.
 *
 * \return              The corresponding ECDSA signature algorithm.
 * \return              Unspecified if \p hash_alg is not a supported
 *                      hash algorithm.
 */
#define PSA_ALG_ECDSA(hash_alg)                                 \
    (PSA_ALG_ECDSA_BASE | ((hash_alg) & PSA_ALG_HASH_MASK))

#define PSA_ALG_ECDSA_ANY       PSA_ALG_ECDSA_BASE

#define PSA_ALG_RSA_PKCS1V15_CRYPT ((psa_algorithm_t)0x07000200)
#define PSA_ALG_FFDH ((psa_algorithm_t)0x09010000)
#define PSA_ALG_ECDH ((psa_algorithm_t)0x09020000)

#define PSA_ALG_DETERMINISTIC_ECDSA(hash_alg) /* specification-defined value */
#define PSA_ALG_FULL_LENGTH_MAC(mac_alg) /* specification-defined value */
#define PSA_ALG_RSA_OAEP(hash_alg) /* specification-defined value */
#define PSA_ALG_RSA_PKCS1V15_SIGN(hash_alg) /* specification-defined value */
#define PSA_ALG_RSA_PSS(hash_alg) /* specification-defined value */


#define PSA_ALG_TLS12_PRF(hash_alg) /* specification-defined value */
#define PSA_ALG_TLS12_PSK_TO_MS(hash_alg) /* specification-defined value */
#define PSA_ALG_TRUNCATED_MAC(mac_alg, mac_length) \
/* specification-defined value */


#define PSA_ASYMMETRIC_DECRYPT_OUTPUT_MAX_SIZE \
/* implementation-defined value */
#define PSA_ASYMMETRIC_DECRYPT_OUTPUT_SIZE(key_type, key_bits, alg) \
/* implementation-defined value */
#define PSA_ASYMMETRIC_ENCRYPT_OUTPUT_MAX_SIZE \
/* implementation-defined value */
#define PSA_ASYMMETRIC_ENCRYPT_OUTPUT_SIZE(key_type, key_bits, alg) \
/* implementation-defined value */

#define PSA_GET_KEY_TYPE_BLOCK_SIZE_EXPONENT(type)      \
    (((type) >> 8) & 7)

/** The block size of a block cipher.
 *
 * \param type  A cipher key type (value of type #psa_key_type_t).
 *
 * \return      The block size for a block cipher, or 1 for a stream cipher.
 *              The return value is undefined if \p type is not a supported
 *              cipher key type.
 *
 * \note It is possible to build stream cipher algorithms on top of a block
 *       cipher, for example CTR mode (#PSA_ALG_CTR).
 *       This macro only takes the key type into account, so it cannot be
 *       used to determine the size of the data that #psa_cipher_update()
 *       might buffer for future processing in general.
 *
 * \note This macro returns a compile-time constant if its argument is one.
 *
 * \warning This macro may evaluate its argument multiple times.
 */
#define PSA_BLOCK_CIPHER_BLOCK_LENGTH(type)                                     \
    (((type) & PSA_KEY_TYPE_CATEGORY_MASK) == PSA_KEY_TYPE_CATEGORY_SYMMETRIC ? \
     1u << PSA_GET_KEY_TYPE_BLOCK_SIZE_EXPONENT(type) :                         \
     0u)

#define PSA_BLOCK_CIPHER_BLOCK_MAX_SIZE /* implementation-defined value */
#define PSA_CIPHER_DECRYPT_OUTPUT_MAX_SIZE(input_length) \
/* implementation-defined value */
#define PSA_CIPHER_DECRYPT_OUTPUT_SIZE(key_type, alg, input_length) \
/* implementation-defined value */
#define PSA_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE(input_length) \
/* implementation-defined value */
#define PSA_CIPHER_ENCRYPT_OUTPUT_SIZE(key_type, alg, input_length) \
/* implementation-defined value */
#define PSA_CIPHER_FINISH_OUTPUT_MAX_SIZE /* implementation-defined value */
#define PSA_CIPHER_FINISH_OUTPUT_SIZE(key_type, alg) \
/* implementation-defined value */

/** The default IV size for a cipher algorithm, in bytes.
 *
 * The IV that is generated as part of a call to #psa_cipher_encrypt() is always
 * the default IV length for the algorithm.
 *
 * This macro can be used to allocate a buffer of sufficient size to
 * store the IV output from #psa_cipher_generate_iv() when using
 * a multi-part cipher operation.
 *
 * See also #PSA_CIPHER_IV_MAX_SIZE.
 *
 * \warning This macro may evaluate its arguments multiple times or
 *          zero times, so you should not pass arguments that contain
 *          side effects.
 *
 * \param key_type  A symmetric key type that is compatible with algorithm \p alg.
 *
 * \param alg       A cipher algorithm (\c PSA_ALG_XXX value such that #PSA_ALG_IS_CIPHER(\p alg) is true).
 *
 * \return The default IV size for the specified key type and algorithm.
 *         If the algorithm does not use an IV, return 0.
 *         If the key type or cipher algorithm is not recognized,
 *         or the parameters are incompatible, return 0.
 */
#define PSA_CIPHER_IV_LENGTH(key_type, alg) \
    (PSA_BLOCK_CIPHER_BLOCK_LENGTH(key_type) > 1 && \
        ((alg) == PSA_ALG_CBC_NO_PADDING) ? 16 : 0)

#define PSA_CIPHER_IV_MAX_SIZE /* implementation-defined value */
#define PSA_CIPHER_UPDATE_OUTPUT_MAX_SIZE(input_length) \
/* implementation-defined value */
#define PSA_CIPHER_UPDATE_OUTPUT_SIZE(key_type, alg, input_length) \
/* implementation-defined value */

#define PSA_DH_FAMILY_RFC7919 ((psa_dh_family_t) 0x03)
#define PSA_ECC_FAMILY_BRAINPOOL_P_R1 ((psa_ecc_family_t) 0x30)
#define PSA_ECC_FAMILY_FRP ((psa_ecc_family_t) 0x33)
#define PSA_ECC_FAMILY_MONTGOMERY ((psa_ecc_family_t) 0x41)
#define PSA_ECC_FAMILY_SECP_K1 ((psa_ecc_family_t) 0x17)
#define PSA_ECC_FAMILY_SECP_R1 ((psa_ecc_family_t) 0x12)
#define PSA_ECC_FAMILY_SECP_R2 ((psa_ecc_family_t) 0x1b)
#define PSA_ECC_FAMILY_SECT_K1 ((psa_ecc_family_t) 0x27)
#define PSA_ECC_FAMILY_SECT_R1 ((psa_ecc_family_t) 0x22)
#define PSA_ECC_FAMILY_SECT_R2 ((psa_ecc_family_t) 0x2b)

#define PSA_HASH_BLOCK_LENGTH(alg) /* implementation-defined value */
#define PSA_HASH_MAX_SIZE (64) /* implementation-defined value */
#define PSA_HASH_SUSPEND_ALGORITHM_FIELD_LENGTH ((size_t)4)
#define PSA_HASH_SUSPEND_HASH_STATE_FIELD_LENGTH(alg) \
/* specification-defined value */
#define PSA_HASH_SUSPEND_INPUT_LENGTH_FIELD_LENGTH(alg) \
/* specification-defined value */
#define PSA_HASH_SUSPEND_OUTPUT_MAX_SIZE /* implementation-defined value */
#define PSA_HASH_SUSPEND_OUTPUT_SIZE(alg) /* specification-defined value */

//#define PSA_KEY_ATTRIBUTES_INIT /* implementation-defined value */
#define PSA_KEY_DERIVATION_INPUT_CONTEXT /* implementation-defined value */
#define PSA_KEY_DERIVATION_INPUT_INFO /* implementation-defined value */
#define PSA_KEY_DERIVATION_INPUT_LABEL /* implementation-defined value */
#define PSA_KEY_DERIVATION_INPUT_SALT /* implementation-defined value */
#define PSA_KEY_DERIVATION_INPUT_SECRET /* implementation-defined value */
#define PSA_KEY_DERIVATION_INPUT_SEED /* implementation-defined value */
#define PSA_KEY_DERIVATION_OPERATION_INIT /* implementation-defined value */
#define PSA_KEY_DERIVATION_UNLIMITED_CAPACITY \
/* implementation-defined value */
#define PSA_KEY_ID_NULL ((psa_key_id_t)0)
#define PSA_KEY_ID_USER_MAX ((psa_key_id_t)0x3fffffff)
#define PSA_KEY_ID_USER_MIN ((psa_key_id_t)0x00000001)
#define PSA_KEY_ID_VENDOR_MAX ((psa_key_id_t)0x7fffffff)
#define PSA_KEY_ID_VENDOR_MIN ((psa_key_id_t)0x40000000)

#define PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(persistence, location) \
((location) << 8 | (persistence))

#define PSA_KEY_LIFETIME_GET_LOCATION(lifetime) \
((psa_key_location_t) ((lifetime) >> 8))

#define PSA_KEY_LIFETIME_GET_PERSISTENCE(lifetime) \
((psa_key_persistence_t) ((lifetime) & 0x000000ff))

#define PSA_KEY_LIFETIME_IS_VOLATILE(lifetime) \
(PSA_KEY_LIFETIME_GET_PERSISTENCE(lifetime) == PSA_KEY_PERSISTENCE_VOLATILE)

#define PSA_KEY_LIFETIME_PERSISTENT ((psa_key_lifetime_t) 0x00000001)
#define PSA_KEY_LIFETIME_VOLATILE ((psa_key_lifetime_t) 0x00000000)

#define PSA_KEY_LOCATION_LOCAL_STORAGE          ((psa_key_location_t) 0x000000)
#define PSA_KEY_LOCATION_PRIMARY_SECURE_ELEMENT ((psa_key_location_t) 0x000001)

#define PSA_KEY_LOCATION_VENDOR_FLAG            ((psa_key_location_t)0x800000)

#define PSA_KEY_LOCATION_SE_MIN (PSA_KEY_LOCATION_VENDOR_FLAG)
#define PSA_KEY_LOCATION_SE_MAX ((psa_key_location_t) 0x8000ff)

#define PSA_KEY_PERSISTENCE_DEFAULT ((psa_key_persistence_t) 0x01)
#define PSA_KEY_PERSISTENCE_READ_ONLY ((psa_key_persistence_t) 0xff)
#define PSA_KEY_PERSISTENCE_VOLATILE ((psa_key_persistence_t) 0x00)

/** Vendor-defined key type flag.
 *
 * Key types defined by this standard will never have the
 * #PSA_KEY_TYPE_VENDOR_FLAG bit set. Vendors who define additional key types
 * must use an encoding with the #PSA_KEY_TYPE_VENDOR_FLAG bit set and should
 * respect the bitwise structure used by standard encodings whenever practical.
 */
#define PSA_KEY_TYPE_VENDOR_FLAG                    ((psa_key_type_t)0x8000)

#define PSA_KEY_TYPE_CATEGORY_MASK                  ((psa_key_type_t)0x7000)
#define PSA_KEY_TYPE_CATEGORY_RAW                   ((psa_key_type_t)0x1000)
#define PSA_KEY_TYPE_CATEGORY_SYMMETRIC             ((psa_key_type_t)0x2000)
#define PSA_KEY_TYPE_CATEGORY_PUBLIC_KEY            ((psa_key_type_t)0x4000)
#define PSA_KEY_TYPE_CATEGORY_KEY_PAIR              ((psa_key_type_t)0x7000)

#define PSA_KEY_TYPE_CATEGORY_FLAG_PAIR             ((psa_key_type_t)0x3000)

#define PSA_KEY_TYPE_AES ((psa_key_type_t)0x2400)
#define PSA_KEY_TYPE_ARC4 ((psa_key_type_t)0x2002)
#define PSA_KEY_TYPE_CAMELLIA ((psa_key_type_t)0x2403)
#define PSA_KEY_TYPE_CHACHA20 ((psa_key_type_t)0x2004)
#define PSA_KEY_TYPE_DERIVE ((psa_key_type_t)0x1200)
#define PSA_KEY_TYPE_DES ((psa_key_type_t)0x2301)
#define PSA_KEY_TYPE_DH_GET_FAMILY(type) /* specification-defined value */
#define PSA_KEY_TYPE_DH_KEY_PAIR(group) /* specification-defined value */
#define PSA_KEY_TYPE_DH_PUBLIC_KEY(group) /* specification-defined value */
#define PSA_KEY_TYPE_ECC_GET_FAMILY(type) /* specification-defined value */

#define PSA_KEY_TYPE_ECC_PUBLIC_KEY_BASE            ((psa_key_type_t)0x4100)
#define PSA_KEY_TYPE_ECC_KEY_PAIR_BASE              ((psa_key_type_t)0x7100)
#define PSA_KEY_TYPE_ECC_CURVE_MASK                 ((psa_key_type_t)0x00ff)
/** Elliptic curve key pair.
 *
 * The size of an elliptic curve key is the bit size associated with the curve,
 * i.e. the bit size of *q* for a curve over a field *F<sub>q</sub>*.
 * See the documentation of `PSA_ECC_FAMILY_xxx` curve families for details.
 *
 * \param curve     A value of type ::psa_ecc_family_t that
 *                  identifies the ECC curve to be used.
 */
#define PSA_KEY_TYPE_ECC_KEY_PAIR(curve)         \
    (PSA_KEY_TYPE_ECC_KEY_PAIR_BASE | (curve))
/** Elliptic curve public key.
 *
 * The size of an elliptic curve public key is the same as the corresponding
 * private key (see #PSA_KEY_TYPE_ECC_KEY_PAIR and the documentation of
 * `PSA_ECC_FAMILY_xxx` curve families).
 *
 * \param curve     A value of type ::psa_ecc_family_t that
 *                  identifies the ECC curve to be used.
 */
#define PSA_KEY_TYPE_ECC_PUBLIC_KEY(curve)              \
    (PSA_KEY_TYPE_ECC_PUBLIC_KEY_BASE | (curve))

/** Elliptic curve key pair. */
#define PSA_KEY_TYPE_ECC_KEY_PAIR(curve)         \
    (PSA_KEY_TYPE_ECC_KEY_PAIR_BASE | (curve))

/** Elliptic curve public key. */
#define PSA_KEY_TYPE_ECC_PUBLIC_KEY(curve)              \
    (PSA_KEY_TYPE_ECC_PUBLIC_KEY_BASE | (curve))

/** Whether a key type is an elliptic curve key (pair or public-only). */
#define PSA_KEY_TYPE_IS_ECC(type)                                       \
    ((PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(type) &                        \
      ~PSA_KEY_TYPE_ECC_CURVE_MASK) == PSA_KEY_TYPE_ECC_PUBLIC_KEY_BASE)

/** Whether a key type is an elliptic curve key pair. */
#define PSA_KEY_TYPE_IS_ECC_KEY_PAIR(type)                               \
    (((type) & ~PSA_KEY_TYPE_ECC_CURVE_MASK) ==                         \
     PSA_KEY_TYPE_ECC_KEY_PAIR_BASE)

/** Whether a key type is an elliptic curve public key. */
#define PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY(type)                            \
    (((type) & ~PSA_KEY_TYPE_ECC_CURVE_MASK) ==                         \
     PSA_KEY_TYPE_ECC_PUBLIC_KEY_BASE)

/** The public key type corresponding to a key pair type.
 *
 * You may also pass a key pair type as \p type, it will be left unchanged.
 *
 * \param type      A public key type or key pair type.
 *
 * \return          The corresponding public key type.
 *                  If \p type is not a public key or a key pair,
 *                  the return value is undefined.
 */
#define PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(type)        \
    ((type) & ~PSA_KEY_TYPE_CATEGORY_FLAG_PAIR)

#define PSA_KEY_TYPE_HMAC ((psa_key_type_t)0x1100)
#define PSA_KEY_TYPE_IS_ASYMMETRIC(type) /* specification-defined value */
#define PSA_KEY_TYPE_IS_DH(type) /* specification-defined value */
#define PSA_KEY_TYPE_IS_DH_KEY_PAIR(type) /* specification-defined value */
#define PSA_KEY_TYPE_IS_DH_PUBLIC_KEY(type) /* specification-defined value */

#define PSA_KEY_TYPE_IS_KEY_PAIR(type) \
    (   (type == PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1)) || \
        (type == PSA_KEY_TYPE_RSA_KEY_PAIR))

#define PSA_KEY_TYPE_IS_PUBLIC_KEY(type) /* specification-defined value */
#define PSA_KEY_TYPE_IS_RSA(type) /* specification-defined value */

/** Whether a key type is an unstructured array of bytes.
 *
 * This encompasses both symmetric keys and non-key data.
 */
#define PSA_KEY_TYPE_IS_UNSTRUCTURED(type) \
    (((type) & PSA_KEY_TYPE_CATEGORY_MASK) == PSA_KEY_TYPE_CATEGORY_RAW || \
     ((type) & PSA_KEY_TYPE_CATEGORY_MASK) == PSA_KEY_TYPE_CATEGORY_SYMMETRIC)

#define PSA_KEY_TYPE_KEY_PAIR_OF_PUBLIC_KEY(type) \
/* specification-defined value */
#define PSA_KEY_TYPE_NONE ((psa_key_type_t)0x0000)

#define PSA_KEY_TYPE_RAW_DATA ((psa_key_type_t)0x1001)
#define PSA_KEY_TYPE_RSA_KEY_PAIR ((psa_key_type_t)0x7001)
#define PSA_KEY_TYPE_RSA_PUBLIC_KEY ((psa_key_type_t)0x4001)
#define PSA_KEY_TYPE_SM4 ((psa_key_type_t)0x2405)

#define PSA_KEY_USAGE_CACHE ((psa_key_usage_t)0x00000004)
#define PSA_KEY_USAGE_COPY ((psa_key_usage_t)0x00000002)
#define PSA_KEY_USAGE_DECRYPT ((psa_key_usage_t)0x00000200)
#define PSA_KEY_USAGE_DERIVE ((psa_key_usage_t)0x00004000)
#define PSA_KEY_USAGE_ENCRYPT ((psa_key_usage_t)0x00000100)
#define PSA_KEY_USAGE_EXPORT ((psa_key_usage_t)0x00000001)
#define PSA_KEY_USAGE_SIGN_HASH ((psa_key_usage_t)0x00001000)
#define PSA_KEY_USAGE_SIGN_MESSAGE ((psa_key_usage_t)0x00000400)
#define PSA_KEY_USAGE_VERIFY_HASH ((psa_key_usage_t)0x00002000)
#define PSA_KEY_USAGE_VERIFY_MESSAGE ((psa_key_usage_t)0x00000800)

#define PSA_MAC_LENGTH(key_type, key_bits, alg) \
/* implementation-defined value */
#define PSA_MAC_MAX_SIZE /* implementation-defined value */
#define PSA_MAC_OPERATION_INIT /* implementation-defined value */
#define PSA_RAW_KEY_AGREEMENT_OUTPUT_MAX_SIZE \
/* implementation-defined value */
#define PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE(key_type, key_bits) \
/* implementation-defined value */
#define PSA_SIGNATURE_MAX_SIZE /* implementation-defined value */
#define PSA_TLS12_PSK_TO_MS_PSK_MAX_SIZE /* implementation-defined value */

/* TODO: Adapt max key length to algorithm in use */
#define PSA_MAX_KEY_LENGTH  (128)

/**
 * @brief The action was completed successfully.
 */
#define PSA_SUCCESS ((psa_status_t)0)

/**
 * @brief An error occurred that does not correspond to any defined failure cause.
 */
#define PSA_ERROR_GENERIC_ERROR ((psa_status_t)-132)

/**
 * @brief The requested operation or a parameter is not supported by this implementation.
 */
#define PSA_ERROR_NOT_SUPPORTED ((psa_status_t)-134)

/**
 * @brief The requested action is denied by a policy.
 */
#define PSA_ERROR_NOT_PERMITTED ((psa_status_t)-133)

/**
 * @brief An output buffer is too small.
 */
#define PSA_ERROR_BUFFER_TOO_SMALL ((psa_status_t)-138)

/**
 * @brief Asking for an item that already exists.
 */
#define PSA_ERROR_ALREADY_EXISTS ((psa_status_t)-139)

/**
 * @brief Asking for an item that doesn’t exist.
 */
#define PSA_ERROR_DOES_NOT_EXIST ((psa_status_t)-140)

/**
 * @brief The requested action cannot be performed in the current state.
 */
#define PSA_ERROR_BAD_STATE ((psa_status_t)-137)

/**
 * @brief The parameters passed to the function are invalid.
 */
#define PSA_ERROR_INVALID_ARGUMENT ((psa_status_t)-135)

/**
 * @brief There is not enough runtime memory.
 */
#define PSA_ERROR_INSUFFICIENT_MEMORY ((psa_status_t)-141)

/**
 * @brief There is not enough persistent storage.
 */
#define PSA_ERROR_INSUFFICIENT_STORAGE ((psa_status_t)-142)

/**
 * @brief There was a communication failure inside the implementation.
 */
#define PSA_ERROR_COMMUNICATION_FAILURE ((psa_status_t)-145)

/**
 * @brief There was a storage failure that might have led to data loss.
 */
#define PSA_ERROR_STORAGE_FAILURE ((psa_status_t)-146)

/**
 * @brief Stored data has been corrupted.
 */
#define PSA_ERROR_DATA_CORRUPT ((psa_status_t)-152)

/**
 * @brief Data read from storage is not valid for the implementation.
 */
#define PSA_ERROR_DATA_INVALID ((psa_status_t)-153)

/**
 * @brief A hardware failure was detected.
 */
#define PSA_ERROR_HARDWARE_FAILURE ((psa_status_t)-147)

/**
 * @brief A tampering attempt was detected.
 */
#define PSA_ERROR_CORRUPTION_DETECTED ((psa_status_t)-151)

/**
 * @brief There is not enough entropy to generate random data needed
 * for the requested action.
 */
#define PSA_ERROR_INSUFFICIENT_ENTROPY ((psa_status_t)-148)

/**
 * @brief The signature, MAC or hash is incorrect.
 */
#define PSA_ERROR_INVALID_SIGNATURE ((psa_status_t)-149)

/**
 * @brief The decrypted padding is incorrect.
 */
#define PSA_ERROR_INVALID_PADDING ((psa_status_t)-150)

/**
 * @brief Return this error when there’s insufficient data when
 * attempting to read from a resource.
 */
#define PSA_ERROR_INSUFFICIENT_DATA ((psa_status_t)-143)

/**
 * @brief The key identifier is not valid.
 */
#define PSA_ERROR_INVALID_HANDLE ((psa_status_t)-136)


/**
 * @brief An invalid algorithm identifier value.
 *
 * Zero is not the encoding of any algorithm.
 */
#define PSA_ALG_NONE ((psa_algorithm_t)0)

/* PSA Hash Algorithms*/

/**
 * @brief The MD2 message-digest algorithm.
 *
 * \warning The MD2 hash is weak and deprecated and is only recommended
 * for use in legacy protocols.
 */
#define PSA_ALG_MD2 ((psa_algorithm_t)0x02000001)

/**
 * @brief The MD4 message-digest algorithm.
 *
 * \warning The MD4 hash is weak and deprecated and is only recommended
 * for use in legacy protocols.
 */
#define PSA_ALG_MD4 ((psa_algorithm_t)0x02000002)

/**
 * @brief The MD5 message-digest algorithm.
 *
 * \warning The MD5 hash is weak and deprecated and is only recommended
 * for use in legacy protocols.
 */
#define PSA_ALG_MD5 ((psa_algorithm_t)0x02000003)

/**
 * @brief The RIPEMD-160 message-digest algorithm.
 */
#define PSA_ALG_RIPEMD160 ((psa_algorithm_t)0x02000004)

/**
 * @brief The SHA-1 message-digest algorithm.
 *
 * \warning The SHA-1 hash is weak and deprecated and is only recommended
 * for use in legacy protocols.
 */
#define PSA_ALG_SHA_1 ((psa_algorithm_t)0x02000005)

/**
 * @brief The SHA-224 message-digest algorithm.
 */
#define PSA_ALG_SHA_224     ((psa_algorithm_t)0x02000008) /** SHA-224 */

/**
 * @brief The SHA-256 message-digest algorithm.
 */
#define PSA_ALG_SHA_256     ((psa_algorithm_t)0x02000009) /** SHA-256 */

/**
 * @brief The SHA-384 message-digest algorithm.
 */
#define PSA_ALG_SHA_384     ((psa_algorithm_t)0x0200000a) /** SHA-384 */

/**
 * @brief The SHA-512 message-digest algorithm.
 */
#define PSA_ALG_SHA_512     ((psa_algorithm_t)0x0200000b) /** SHA-512 */

/**
 * @brief The SHA-512/224 message-digest algorithm.
 */
#define PSA_ALG_SHA_512_224 ((psa_algorithm_t)0x0200000c) /** SHA-512/224 */

/**
 * @brief The SHA-512/256 message-digest algorithm.
 */
#define PSA_ALG_SHA_512_256 ((psa_algorithm_t)0x0200000d) /** SHA-512/256 */

/**
 * @brief The SHA3-224 message-digest algorithm.
 */
#define PSA_ALG_SHA3_224    ((psa_algorithm_t)0x02000010) /** SHA-3-224 */

/**
 * @brief The SHA3-256 message-digest algorithm.
 */
#define PSA_ALG_SHA3_256    ((psa_algorithm_t)0x02000011) /** SHA-3-256 */

/**
 * @brief The SHA3-384 message-digest algorithm.
 */
#define PSA_ALG_SHA3_384    ((psa_algorithm_t)0x02000012) /** SHA-3-384 */

/**
 * @brief The SHA3-512 message-digest algorithm.
 */
#define PSA_ALG_SHA3_512    ((psa_algorithm_t)0x02000013) /** SHA-3-512 */

/**
 * @brief The SM3 message-digest algorithm.
 */
#define PSA_ALG_SM3         ((psa_algorithm_t)0x02000014) /** SM3 */


#endif /* PSA_CRYPTO_VALUES_H */
