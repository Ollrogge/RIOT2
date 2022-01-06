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
 * @brief       PSA Crypto MAC APIs
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#ifndef PSA_MAC_H
#define PSA_MAC_H

#include "kernel_defines.h"
#include "psa/crypto.h"
#include "psa/crypto_contexts.h"

#if IS_ACTIVE(CONFIG_PSA_MAC_HMAC_SHA_256)
psa_status_t psa_mac_compute_hmac_sha256(   const psa_key_attributes_t * attributes,
                                    const uint8_t * key_buffer,
                                    size_t key_buffer_size,
                                    const uint8_t * input,
                                    size_t input_length,
                                    uint8_t * mac,
                                    size_t mac_size,
                                    size_t * mac_length);
#endif /* CONFIG_PSA_MAC_HMAC_SHA_256 */

#endif /* PSA_MAC_H */
