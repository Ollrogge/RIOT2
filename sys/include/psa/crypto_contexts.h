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

#include "psa/crypto_includes.h"

typedef union {
    unsigned dummy; /* Make the union non-empty even with no supported algorithms. */
#if IS_ACTIVE(CONFIG_HASHES_MD5)
    psa_hashes_md5_ctx_t md5;
#endif
#if IS_ACTIVE(CONFIG_HASHES_SHA1)
    psa_hashes_sha1_ctx_t sha1;
#endif
#if IS_ACTIVE(CONFIG_HASHES_SHA224)
    psa_hashes_sha224_ctx_t sha224;
#endif
#if IS_ACTIVE(CONFIG_HASHES_SHA256)
    psa_hashes_sha256_ctx_t sha256;
#endif
} psa_hash_context_t;

typedef union {
    unsigned dummy;
#if IS_ACTIVE(CONFIG_PSA_CRYPTO_SECURE_ELEMENT)
    uint64_t se_key_slot;
#endif
#if IS_ACTIVE(CONFIG_PSA_CIPHER_AES_KEY_SIZE_128)
    psa_cipher_aes_128_ctx_t aes_128;
#endif
#if IS_ACTIVE(CONFIG_PSA_CIPHER_AES_KEY_SIZE_192)
    psa_cipher_aes_192_ctx_t aes_192;
#endif
#if IS_ACTIVE(CONFIG_PSA_CIPHER_AES_KEY_SIZE_256)
    psa_cipher_aes_256_ctx_t aes_256;
#endif
} psa_cipher_context_t;

#endif /* CRYPTO_CONTEXT_H */
