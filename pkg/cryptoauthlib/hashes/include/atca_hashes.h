/*
 * Copyright (C) 2021 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     pkg_cryptoauthlib sys_psa_crypto
 * @{
 *
 * @file
 * @brief       Function declarations for ATCA glue code for PSA Crypto
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#ifndef ATCA_HASHES_H
#define ATCA_HASHES_H

#include "cryptoauthlib.h"
#include "psa/crypto.h"

typedef struct {
    psa_algorithm_t alg;
    atca_sha256_ctx_t ctx;
} psa_hash_atca_operation_t;

psa_status_t atca_hash_setup(psa_hash_atca_operation_t * operation,
                                           psa_algorithm_t alg);

psa_status_t atca_hash_update(psa_hash_atca_operation_t * operation,
                             const uint8_t * input,
                             size_t input_length);

psa_status_t atca_hash_finish(psa_hash_atca_operation_t * operation,
                             uint8_t * hash,
                             size_t hash_size,
                             size_t * hash_length);

#endif /* ATCA_HASHES_H */