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
#include "crypto_contexts.h"

struct psa_hash_operation_s
{
    uint8_t driver_id;
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
    uint8_t driver_id;
    uint8_t iv_required : 1;
    uint8_t iv_set : 1;
    uint8_t default_iv_length;
    psa_cipher_context_t ctx;
};

#define PSA_CIPHER_OPERATION_INIT {0}

static inline struct psa_cipher_operation_s psa_cipher_operation_init(void)
{
    const struct psa_cipher_operation_s v = PSA_CIPHER_OPERATION_INIT;
    return v;
}

#endif /* PSA_CRYPTO_STRUCT_H */
