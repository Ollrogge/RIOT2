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

#ifndef PSA_BUILTIN_HASHES_H
#define PSA_BUILTIN_HASHES_H

#include "kernel_defines.h"

#include "crypto.h"

#include "hashes/md5.h"
#include "hashes/sha1.h"
#include "hashes/sha224.h"
#include "hashes/sha256.h"

typedef union {
    unsigned dummy; /* Make the union non-empty even with no supported algorithms. */

#if IS_ACTIVE(CONFIG_SW_HASH_MD5)
    md5_ctx_t md5;
#endif
#if IS_ACTIVE(CONFIG_SW_HASH_SHA1)
    sha1_context sha1;
#endif
#if IS_ACTIVE(CONFIG_SW_HASH_SHA224)
    sha224_context_t sha224;
#endif
#if IS_ACTIVE(CONFIG_SW_HASH_SHA256)
    sha256_context_t sha256;
#endif
} psa_builtin_hash_operation_t;

psa_status_t psa_builtin_hash_setup(psa_hash_operation_t * operation,
                                           psa_algorithm_t alg);

psa_status_t psa_builtin_hash_update(psa_hash_operation_t * operation,
                             const uint8_t * input,
                             size_t input_length);

psa_status_t psa_builtin_hash_finish(psa_hash_operation_t * operation,
                             uint8_t * hash,
                             size_t hash_size,
                             size_t * hash_length);

#endif /* PSA_BUILTIN_HASHES_H */
