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
#include "crypto_driver_wrapper.h"
#include "crypto_contexts.h"

struct psa_hash_operation_s
{
    uint8_t driver_id;
    psa_algorithm_t alg;
    union {
        unsigned dummy; /* Make the union non-empty even with no supported algorithms. */
        psa_builtin_hash_operation_t builtin_ctx;
    #if IS_ACTIVE(CONFIG_PERIPH_HASHES)
        psa_hash_periph_operation_t periph_ctx;
    #endif
    #if IS_ACTIVE(CONFIG_MODULE_CRYPTOAUTHLIB_HASHES)
        psa_hash_atca_operation_t atca_ctx;
    #endif
    } ctx;
};

#define PSA_HASH_OPERATION_INIT {0}

static inline struct psa_hash_operation_s psa_hash_operation_init( void )
{
    const struct psa_hash_operation_s v = PSA_HASH_OPERATION_INIT;
    return( v );
}

struct psa_key_attributes_s
{
    psa_algorithm_t alg;
    union
    {
        unsigned dummy; /* Make the union non-empty even with no supported algorithms. */
    } ctx;
};

#define PSA_KEY_ATTRIBUTES_INIT {0, {0}}//{PSA_CORE_KEY_ATTRIBUTES_INIT, NULL, 0}

static inline struct psa_key_attributes_s psa_key_attributes_init( void )
{
    const struct psa_key_attributes_s v = PSA_KEY_ATTRIBUTES_INIT;
    return( v );
}

#endif /* PSA_CRYPTO_STRUCT_H */
