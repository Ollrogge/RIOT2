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
 * @brief       Structure definitions for PSA Crypto
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#ifndef PSA_CRYPTO_STRUCT_H
#define PSA_CRYPTO_STRUCT_H

#include "crypto_types.h"
#include "crypto_sizes.h"
#include "crypto_contexts.h"

struct psa_hash_operation_s
{
    psa_algorithm_t alg;
    psa_hash_context_t ctx;
};

#define PSA_HASH_OPERATION_INIT {0}

static inline struct psa_hash_operation_s psa_hash_operation_init(void)
{
    const struct psa_hash_operation_s v = PSA_HASH_OPERATION_INIT;
    return v;
}

struct psa_key_policy_s
{
    psa_key_usage_t usage;
    psa_algorithm_t alg;
};
typedef struct psa_key_policy_s psa_key_policy_t;

struct psa_key_attributes_s
{
    psa_key_type_t type;
    psa_key_bits_t bits;
    psa_key_lifetime_t lifetime;
    psa_key_id_t id;
    psa_key_policy_t policy;
};

#define PSA_KEY_ATTRIBUTES_INIT {0}//{PSA_CORE_KEY_ATTRIBUTES_INIT, NULL, 0}

static inline struct psa_key_attributes_s psa_key_attributes_init(void)
{
    const struct psa_key_attributes_s v = PSA_KEY_ATTRIBUTES_INIT;
    return v;
}

struct psa_cipher_operation_s
{
    uint8_t iv_required : 1;
    uint8_t iv_set : 1;
    uint8_t default_iv_length;
    psa_algorithm_t alg;
    psa_cipher_context_t ctx;
};

#define PSA_CIPHER_OPERATION_INIT {0}

static inline struct psa_cipher_operation_s psa_cipher_operation_init(void)
{
    const struct psa_cipher_operation_s v = PSA_CIPHER_OPERATION_INIT;
    return v;
}

/**
 * @brief Structure to hold an asymmetric public key or a reference to an ECC public key
 *
 * When is_plain_key == 0, the key is stored in protected memory and pub_key_data
 * contains a slot number. This is the default value, as all key slots are initialized with 0.
 *
 * When is_plain_key == 1, pub_key_data contains an actual key.
 */
struct psa_asym_pub_key_s {
    uint8_t data[PSA_EXPORT_PUBLIC_KEY_MAX_SIZE];
    uint8_t is_plain_key;
    size_t bytes;
};

/**
 * @brief Structure to hold an asymmetric private and public key pair.
 *
 * priv_key_data contains either an actual private key, when key is stored locally,
 * or a slot number referencing to an actual key in protected memory.
 *
 * The structure holds a psa_asym_pub_key_t struct, which contains the actual public key,
 * if it's returned by the driver in use. Otherwise this structure stays empty.
 */
struct psa_asym_keypair_s {
    uint8_t priv_key_data[PSA_MAX_PRIV_KEY_SIZE]; /*!< Contains private key or, in case of SE, slot number of private key */
    size_t priv_key_bytes;
    psa_asym_pub_key_t pub_key; /*!< Contains public key material */
};

/**
 * @brief Structure to hold an unstructured key (e.g. AES or DES)
 */
struct psa_unstructured_key_s {
    uint8_t data[PSA_MAX_KEY_DATA_SIZE];
    size_t bytes;
};
#endif /* PSA_CRYPTO_STRUCT_H */
