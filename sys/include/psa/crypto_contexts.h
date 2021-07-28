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
 * @brief       Context definitions for PSA Crypto
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#ifndef CRYPTO_CONTEXT_H
#define CRYPTO_CONTEXT_H

#include "kernel_defines.h"

#if IS_ACTIVE(CONFIG_PERIPH_HASHES)
#include "periph_hashes.h"
#endif

#if IS_ACTIVE(CONFIG_MODULE_CRYPTOAUTHLIB_HASHES)
#include "atca_hashes.h"
#endif

#include "crypto_software_contexts.h"

typedef union {
    unsigned dummy; /* Make the union non-empty even with no supported algorithms. */
    psa_software_hash_operation_t sw_ctx;
#if IS_ACTIVE(CONFIG_PERIPH_HASHES)
    psa_hash_periph_operation_t periph_ctx;
#endif
#if IS_ACTIVE(CONFIG_MODULE_CRYPTOAUTHLIB_HASHES)
    psa_hash_atca_operation_t atca_ctx;
#endif
} psa_hash_context_t;

typedef union {
    unsigned dummy;
    psa_software_cipher_operation_t sw_ctx;
#if IS_ACTIVE(CONFIG_PSA_CRYPTO_SECURE_ELEMENT)
    uint64_t se_key_slot;
#endif
} psa_cipher_context_t;

#endif /* CRYPTO_CONTEXT_H */
