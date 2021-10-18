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
 * @brief       Function and type declarations for built-in software hashes for
 *              PSA Crypto
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#ifndef PSA_HASHES_H
#define PSA_HASHES_H

#include "kernel_defines.h"
#include "psa/crypto.h"
#include "psa/crypto_contexts.h"

#if IS_ACTIVE(CONFIG_HASHES_MD5)
psa_status_t psa_hashes_md5_setup(psa_hashes_md5_ctx_t * ctx);

psa_status_t psa_hashes_md5_update(psa_hashes_md5_ctx_t * ctx,
                             const uint8_t * input,
                             size_t input_length);

psa_status_t psa_hashes_md5_finish(psa_hashes_md5_ctx_t * ctx,
                             uint8_t * hash,
                             size_t hash_size,
                             size_t * hash_length);
#endif /* CONFIG_HASHES_MD5 */

#if IS_ACTIVE(CONFIG_HASHES_SHA1)
psa_status_t psa_hashes_sha1_setup(psa_hashes_sha1_ctx_t * ctx);

psa_status_t psa_hashes_sha1_update(psa_hashes_sha1_ctx_t * ctx,
                             const uint8_t * input,
                             size_t input_length);

psa_status_t psa_hashes_sha1_finish(psa_hashes_sha1_ctx_t * ctx,
                             uint8_t * hash,
                             size_t hash_size,
                             size_t * hash_length);
#endif /* CONFIG_HASHES_SHA1 */

#if IS_ACTIVE(CONFIG_HASHES_SHA224)
psa_status_t psa_hashes_sha224_setup(psa_hashes_sha224_ctx_t * ctx);

psa_status_t psa_hashes_sha224_update(psa_hashes_sha224_ctx_t * ctx,
                             const uint8_t * input,
                             size_t input_length);

psa_status_t psa_hashes_sha224_finish(psa_hashes_sha224_ctx_t * ctx,
                             uint8_t * hash,
                             size_t hash_size,
                             size_t * hash_length);
#endif /* CONFIG_HASHES_SHA224 */

#if IS_ACTIVE(CONFIG_HASHES_SHA256)
psa_status_t psa_hashes_sha256_setup(psa_hashes_sha256_ctx_t * ctx);

psa_status_t psa_hashes_sha256_update(psa_hashes_sha256_ctx_t * ctx,
                             const uint8_t * input,
                             size_t input_length);

psa_status_t psa_hashes_sha256_finish(psa_hashes_sha256_ctx_t * ctx,
                             uint8_t * hash,
                             size_t hash_size,
                             size_t * hash_length);
#endif /* CONFIG_HASHES_SHA256 */

#if IS_ACTIVE(CONFIG_HASHES_SHA512)
psa_status_t psa_hashes_sha512_setup(psa_hashes_sha512_ctx_t * ctx);

psa_status_t psa_hashes_sha512_update(psa_hashes_sha512_ctx_t * ctx,
                             const uint8_t * input,
                             size_t input_length);

psa_status_t psa_hashes_sha512_finish(psa_hashes_sha512_ctx_t * ctx,
                             uint8_t * hash,
                             size_t hash_size,
                             size_t * hash_length);
#endif /* CONFIG_HASHES_SHA512 */

#endif /* PSA_HASHES_H */
