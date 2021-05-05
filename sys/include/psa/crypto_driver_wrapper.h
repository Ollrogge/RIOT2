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
 * @brief       Funtion declarations for PSA Crypto Driver Wrapper
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#ifndef PSA_CRYPTO_DRIVER_WRAPPER_H
#define PSA_CRYPTO_DRIVER_WRAPPER_H

#include <stdlib.h>
#include "kernel_defines.h"
#include "crypto.h"

psa_status_t psa_driver_wrapper_hash_setup(psa_hash_operation_t * operation,
                                           psa_algorithm_t alg);

psa_status_t psa_driver_wrapper_hash_update(psa_hash_operation_t * operation,
                             const uint8_t * input,
                             size_t input_length);

psa_status_t psa_driver_wrapper_hash_finish(psa_hash_operation_t * operation,
                             uint8_t * hash,
                             size_t hash_size,
                             size_t * hash_length);

#endif
