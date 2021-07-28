/*
 * Copyright (C) 2021 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     sys_psa_crypto pkg_cifra
 * @{
 *
 * @file
 * @brief
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */
#include <stdio.h>
#include "psa/crypto.h"

psa_status_t psa_software_hash_setup(psa_hash_operation_t * operation,
                                           psa_algorithm_t alg)
{


    return PSA_SUCCESS;
}

psa_status_t psa_software_hash_update(psa_hash_operation_t * operation,
                             const uint8_t * input,
                             size_t input_length)
{


    return PSA_SUCCESS;
}

psa_status_t psa_software_hash_finish(psa_hash_operation_t * operation,
                             uint8_t * hash,
                             size_t hash_size,
                             size_t * hash_length)
{

    return PSA_SUCCESS;
}
