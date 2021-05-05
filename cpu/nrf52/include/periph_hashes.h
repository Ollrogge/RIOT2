/*
 * Copyright (C) 2021 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     sys_psa_crypto cpu_nrf52
 * @{
 *
 * @file
 * @brief       Function declarations and context definition for glue code for
 *              ARM Cryptocell driver support in PSA Crypto
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#ifndef PERIPH_HASHES_H
#define PERIPH_HASHES_H

#include <stdlib.h>

#include "cryptocell_incl/crys_hash.h"
#include "psa/crypto.h"

typedef struct {
    psa_algorithm_t alg;
    CRYS_HASHUserContext_t ctx;
} psa_hash_periph_operation_t;

psa_status_t periph_hash_setup(psa_hash_periph_operation_t * operation,
                                           psa_algorithm_t alg);

psa_status_t periph_hash_update(psa_hash_periph_operation_t * operation,
                             const uint8_t * input,
                             size_t input_length);

psa_status_t periph_hash_finish(psa_hash_periph_operation_t * operation,
                             uint8_t * hash,
                             size_t hash_size,
                             size_t * hash_length);

#endif /* CC_HASHES_H */
