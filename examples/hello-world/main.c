/*
 * Copyright (C) 2014 Freie Universität Berlin
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       Hello World application
 *
 * @author      Kaspar Schleiser <kaspar@schleiser.de>
 * @author      Ludwig Knüpfer <ludwig.knuepfer@fu-berlin.de>
 *
 * @}
 */

#include <stdio.h>
#include <stdint.h>
#include "psa/crypto.h"

#include "cryptocell_util.h"
#include "cryptocell_incl/crys_hash.h"
#include "cryptocell_incl/crys_hash_error.h"

static uint8_t EXPECTED_RESULT_SHA256[] = {
    0xB5, 0xB7, 0x56, 0xD2, 0x6F, 0x8C, 0xDF, 0x6B,
    0xA3, 0xCC, 0xB8, 0x12, 0x5C, 0xE4, 0x4D, 0x0F,
    0xDD, 0x1C, 0x4C, 0xF1, 0x6E, 0x41, 0x9F, 0xED,
    0x52, 0x79, 0x2E, 0x1A, 0x9C, 0x47, 0xDF, 0x2B
};

static unsigned char SHA_TESTSTRING[] = "This is a teststring fore sha256";
static size_t SHA_TESTSTR_SIZE = 32;

CRYS_HASHUserContext_t ctx;
CRYS_HASH_Result_t result;

int main(void)
{
    puts("Hello World!");
    
    cryptocell_enable();
    CRYS_HASH_Init(&ctx, CRYS_HASH_SHA256_mode);
    CRYS_HASH_Update(&ctx, SHA_TESTSTRING, SHA_TESTSTR_SIZE);
    CRYS_HASH_Finish(&ctx, result);
    cryptocell_disable();

    if (memcmp(result, EXPECTED_RESULT_SHA256, SHA256_DIGEST_LENGTH) != 0) {
        printf("SHA-256 Failure\n");
    }
    else {
        printf("SHA-256 Success\n");
    }
    return 0;
}
