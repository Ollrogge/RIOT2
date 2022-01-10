/*
 * Copyright (C) 2022 HAW Hamburg
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
 * @brief       Glue code for ARM Cryptocell driver support in PSA Crypto
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#include "kernel_defines.h"
#include "psa/crypto.h"
#include "psa_periph_error.h"

#include "cryptocell_incl/crys_hmac.h"
#include "cryptocell_incl/crys_hmac_error.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

#if TEST_TIME
#include "periph/gpio.h"
extern gpio_t internal_gpio;

psa_status_t psa_mac_compute_hmac_sha256(   const psa_key_attributes_t * attributes,
                                    const uint8_t * key_buffer,
                                    size_t key_buffer_size,
                                    const uint8_t * input,
                                    size_t input_length,
                                    uint8_t * mac,
                                    size_t mac_size,
                                    size_t * mac_length)
{
    CRYSError_t ret;

    DEBUG("Periph HMAC SHA256\n");
    gpio_set(internal_gpio);
    ret = CRYS_HMAC(CRYS_HASH_SHA256_mode, (uint8_t *) key_buffer, key_buffer_size, (uint8_t *)input, input_length, (uint32_t *) mac);
    gpio_clear(internal_gpio);
    if (ret != CRYS_OK) {
        return CRYS_to_psa_error(ret);
    }

    *mac_length = 32;
    (void) attributes;
    (void) mac_size;
    return PSA_SUCCESS;
}
#else
psa_status_t psa_mac_compute_hmac_sha256(   const psa_key_attributes_t * attributes,
                                    const uint8_t * key_buffer,
                                    size_t key_buffer_size,
                                    const uint8_t * input,
                                    size_t input_length,
                                    uint8_t * mac,
                                    size_t mac_size,
                                    size_t * mac_length)
{
    CRYSError_t ret;

    DEBUG("Periph HMAC SHA256\n");
    ret = CRYS_HMAC(CRYS_HASH_SHA256_mode, (uint8_t *) key_buffer, key_buffer_size, (uint8_t *)input, input_length, (uint32_t *) mac);
    if (ret != CRYS_OK) {
        return CRYS_to_psa_error(ret);
    }

    *mac_length = 32;
    (void) attributes;
    (void) mac_size;
    return PSA_SUCCESS;
}
#endif