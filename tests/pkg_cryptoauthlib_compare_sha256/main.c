/*
 * Copyright (C) 2019 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     tests
 * @{
 *
 * @file
 * @brief       This test was written to compare the runtime of the RIOT software
 *              implementation and the CryptoAuth hardware implementation of SHA-256.
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "hashes/sha256.h"
#include "atca.h"
#include "atca_params.h"

#define SHA256_HASH_SIZE (32)

static uint8_t KEY[] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static uint8_t KEY_LEN = 32;

static uint8_t __attribute__((aligned)) ECB_PLAIN[] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
};
static uint8_t ECB_PLAIN_LEN = 32;

static uint8_t __attribute__((aligned))ECB_CIPHER[] = {
    0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
    0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97,
    0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
    0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97
};
static uint8_t ECB_CIPHER_LEN = 32;

/**
 * Function to call RIOT software implementation of SHA-256
 */
static int test_riot_sha256(uint8_t *teststring, uint16_t len,
                            uint8_t *expected,
                            uint8_t *result)
{
    sha256_context_t ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, (void *)teststring, len);
    sha256_final(&ctx, result);
    return memcmp(expected, result, SHA256_HASH_SIZE);
}

/**
 * Function to call CryptoAuth hardware implementation of SHA-256
 */
static int test_atca_sha(uint8_t *teststring, uint16_t len, uint8_t *expected,
                         uint8_t *result)
{
    ATCA_STATUS status;
    status = atcab_sha_start();
    if (status != ATCA_SUCCESS) {
        printf("SHA Start failed: %x\n", status);
    }
    status = atcab_sha_end(result, len, teststring);
    if (status != ATCA_SUCCESS) {
        printf("SHA End failed: %x\n", status);
    }
    return memcmp(expected, result, SHA256_HASH_SIZE);
}

static int test_atca_calib_aes(void)
{
    ATCA_STATUS status;
    ATCADevice dev;
    size_t offset;
    uint8_t result[ECB_CIPHER_LEN];

    status = atcab_init_ext(&dev, (ATCAIfaceCfg *)&atca_params[0]);
    if (status != ATCA_SUCCESS) {
        printf("Device Init failed: %x\n", status);
    }
    status = calib_nonce_load(dev, NONCE_MODE_TARGET_TEMPKEY, KEY, KEY_LEN);
    if (status != ATCA_SUCCESS) {
        printf("Nonce Load failed: %x\n", status);
    }
    offset = 0;

    do {
        status = calib_aes_encrypt(dev, ATCA_TEMPKEY_KEYID, 0, ECB_PLAIN + offset, result + offset);
        if (status != ATCA_SUCCESS) {
            printf("AES Encrypt failed: %x\n", status);
        }
        offset += 16;
    } while (offset < ECB_PLAIN_LEN);

    return memcmp(ECB_CIPHER, result, ECB_CIPHER_LEN);
}

int main(void)
{
    uint8_t teststring[] = "chili cheese fries";
    uint8_t expected[] =
    { 0x36, 0x46, 0xEF, 0xD6, 0x27, 0x6C, 0x0D, 0xCB, 0x4B, 0x07, 0x73, 0x41,
      0x88, 0xF4, 0x17, 0xB4, 0x38, 0xAA, 0xCF, 0xC6, 0xAE, 0xEF, 0xFA, 0xBE,
      0xF3, 0xA8, 0x5D, 0x67, 0x42, 0x0D, 0xFE, 0xE5 };

    uint8_t result[SHA256_HASH_SIZE];                       /* +3 to fit 1 byte length and 2 bytes checksum */

    memset(result, 0, SHA256_HASH_SIZE);                    /* alles in result auf 0 setzen */

    uint16_t test_string_size = (sizeof(teststring) - 1);   /* -1 to ignore \0 */

    if (test_riot_sha256(teststring, test_string_size, expected, result) == 0) {
        printf("RIOT SHA256: Success\n");
    }
    else {
        printf("RIOT SHA256: Failure.\n");
    }
    atca_delay_us(10);
    memset(result, 0, SHA256_HASH_SIZE);

    if (test_atca_sha(teststring, test_string_size, expected, result) == 0) {
        printf("ATCA SHA256: Success\n");
    }
    else {
        printf("ATCA SHA256: Failure.\n");
    }

    if (test_atca_calib_aes() == 0) {
        printf("ATCA AES ECB: Success\n");
    }
    else {
        printf("ATCA AES ECB: Failure.\n");
    }

    return 0;
}
