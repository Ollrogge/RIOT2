/*
 * Copyright (C) 2021 Freie Universität Berlin
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
 * @brief       PSA Crypto Example Application
 *
 * @author      Kaspar Schleiser <kaspar@schleiser.de>
 * @author      Ludwig Knüpfer <ludwig.knuepfer@fu-berlin.de>
 *
 * @}
 */

#include <stdio.h>
#include <string.h>
#include "psa/crypto.h"

static uint8_t KEY[] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};
static uint8_t KEY_LEN = 16;

#if IS_ACTIVE(CONFIG_PSA_CRYPTO_SECURE_ELEMENT)
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
#else
static uint8_t __attribute__((aligned)) CBC_PLAIN[] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
};
static uint8_t CBC_PLAIN_LEN = 32;

static uint8_t __attribute__((aligned)) CBC_CIPHER[] = {
    0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
    0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
    0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee,
    0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2
};
static uint8_t CBC_CIPHER_LEN = 32;
#endif

#if IS_ACTIVE(CONFIG_CIPHER_AES_128_CBC)
static void example_cipher_aes_cbc(void)
{
    psa_status_t status = PSA_ERROR_DOES_NOT_EXIST;
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_key_lifetime_t lifetime = 0x00000000;
    psa_key_id_t key_id = 0;
    psa_key_usage_t usage = PSA_KEY_USAGE_ENCRYPT;
    size_t iv_size = PSA_CIPHER_IV_LENGTH(PSA_KEY_TYPE_AES, PSA_ALG_CBC_NO_PADDING);
    size_t combined_output_size = CBC_CIPHER_LEN + iv_size;

    uint8_t cipher_out[combined_output_size];
    size_t output_len = 0;

    psa_set_key_lifetime(&attr, lifetime);
    psa_set_key_algorithm(&attr, PSA_ALG_CBC_NO_PADDING);
    psa_set_key_usage_flags(&attr, usage);
    psa_set_key_bits(&attr, 128);
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);

    status = psa_import_key(&attr, KEY, KEY_LEN, &key_id);

    if (status != PSA_SUCCESS) {
        printf("CBC Import failed: %ld\n", status);
        return;
    }

    status = psa_cipher_encrypt(key_id, PSA_ALG_CBC_NO_PADDING, CBC_PLAIN, CBC_PLAIN_LEN, cipher_out, combined_output_size, &output_len);
    if (status != PSA_SUCCESS) {
        printf("CBC Encrypt failed: %ld\n", status);
        return;
    }

    if (memcmp(cipher_out + iv_size, CBC_CIPHER, CBC_CIPHER_LEN)) {
        puts("CBC Encryption failed");
    }
    else {
        puts("CBC Encryption successful");
    }
}
#endif

#if IS_ACTIVE(CONFIG_PSA_CRYPTO_SECURE_ELEMENT)
static void example_prim_se(void)
{
    psa_status_t status = PSA_ERROR_DOES_NOT_EXIST;
    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_key_lifetime_t lifetime = 0x80000000;
    psa_key_id_t key_id = 0;
    psa_key_usage_t usage = PSA_KEY_USAGE_ENCRYPT;

    uint8_t cipher_out[ECB_CIPHER_LEN];
    size_t output_len = 0;

    psa_set_key_lifetime(&attr, lifetime);
    psa_set_key_algorithm(&attr, PSA_ALG_ECB_NO_PADDING);
    psa_set_key_usage_flags(&attr, usage);
    psa_set_key_bits(&attr, 128);
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);

    status = psa_import_key(&attr, KEY, KEY_LEN, &key_id);

    if (status != PSA_SUCCESS) {
        printf("Primary SE Import failed: %ld\n", status);
        return;
    }

    status = psa_cipher_encrypt(key_id, PSA_ALG_ECB_NO_PADDING, ECB_PLAIN, ECB_PLAIN_LEN, cipher_out, ECB_CIPHER_LEN, &output_len);
    if (status != PSA_SUCCESS) {
        printf("Primary SE Encrypt failed: %ld\n", status);
        return;
    }

    if (memcmp(cipher_out, ECB_CIPHER, ECB_CIPHER_LEN)) {
        puts("Primary SE Encryption failed");
    }
    else {
        puts("Primary SE Encryption successful");
    }
}
#endif

#if IS_ACTIVE(CONFIG_CURVE_ECC_P256)
static void example_sign_verify(void)
{
    psa_status_t status = PSA_ERROR_DOES_NOT_EXIST;
    psa_key_id_t privkey_id;
    psa_key_attributes_t privkey_attr = psa_key_attributes_init();
    psa_key_id_t pubkey_id;
    psa_key_attributes_t pubkey_attr = psa_key_attributes_init();

    psa_key_lifetime_t lifetime = 0x00000100;
    psa_key_usage_t usage = PSA_KEY_USAGE_SIGN_HASH;
    psa_key_type_t type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
    psa_algorithm_t alg =  PSA_ALG_ECDSA(PSA_ALG_SHA_256);
    psa_key_bits_t bits = PSA_VENDOR_ECC_MAX_CURVE_BITS;

    uint8_t public_key[PSA_EXPORT_PUBLIC_KEY_MAX_SIZE] = { 0 };
    size_t pubkey_length;

    uint8_t signature[PSA_SIGN_OUTPUT_SIZE(type, bits, alg)];
    size_t sig_length;
    uint8_t msg[PSA_HASH_LENGTH(PSA_ALG_SHA_256)] = { 0x0b };

    psa_set_key_lifetime(&privkey_attr, lifetime);
    psa_set_key_algorithm(&privkey_attr, alg);
    psa_set_key_usage_flags(&privkey_attr, usage);
    psa_set_key_type(&privkey_attr, type);
    psa_set_key_bits(&privkey_attr, bits);

    status = psa_generate_key(&privkey_attr, &privkey_id);
    if (status != PSA_SUCCESS) {
        printf("Primary SE Generate Key failed: %ld\n", status);
        return;
    }

    status = psa_export_public_key(privkey_id, public_key, sizeof(public_key), &pubkey_length);
    if (status != PSA_SUCCESS) {
        printf("Primary SE Export Public Key failed: %ld\n", status);
        return;
    }

    lifetime = 0x80000000;
    psa_set_key_lifetime(&pubkey_attr, lifetime);
    psa_set_key_algorithm(&pubkey_attr, alg);
    psa_set_key_usage_flags(&pubkey_attr, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_bits(&pubkey_attr, 512);
    psa_set_key_type(&pubkey_attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));

    status = psa_import_key(&pubkey_attr, public_key, pubkey_length, &pubkey_id);
    if (status != PSA_SUCCESS) {
        printf("PSA Import Public Key failed: %ld\n", status);
        return;
    }

    status = psa_sign_hash(privkey_id, alg, msg, sizeof(msg), signature, sizeof(signature), &sig_length);
    if (status != PSA_SUCCESS) {
        printf("Primary SE Sign hash failed: %ld\n", status);
        return;
    }

    status = psa_verify_hash(pubkey_id, alg, msg, sizeof(msg), signature, sig_length);
    if (status != PSA_SUCCESS) {
        printf("Primary SE Verify hash failed: %ld\n", status);
        return;
    }
    puts("Sign Verify Successful");
}
#endif

#if IS_ACTIVE(CONFIG_PSA_MULTIPLE_SECURE_ELEMENTS)
static void example_sec_se(void)
{
    psa_status_t status = PSA_ERROR_DOES_NOT_EXIST;

    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_key_lifetime_t lifetime = 0x80000100;
    psa_key_id_t key_id = 0;
    psa_key_usage_t usage = PSA_KEY_USAGE_ENCRYPT;

    uint8_t cipher_out[ECB_CIPHER_LEN];
    size_t output_len = 0;

    psa_set_key_lifetime(&attr, lifetime);
    psa_set_key_algorithm(&attr, PSA_ALG_ECB_NO_PADDING);
    psa_set_key_usage_flags(&attr, usage);
    psa_set_key_bits(&attr, 128);
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);

    status = psa_import_key(&attr, KEY, KEY_LEN, &key_id);

    if (status != PSA_SUCCESS) {
        printf("Secondary SE Import failed: %ld\n", status);
        return;
    }

    status = psa_cipher_encrypt(key_id, PSA_ALG_ECB_NO_PADDING, ECB_PLAIN, ECB_PLAIN_LEN, cipher_out, ECB_CIPHER_LEN, &output_len);
    if (status != PSA_SUCCESS) {
        printf("Secondary SE Encrypt failed: %ld\n", status);
        return;
    }

    if (memcmp(cipher_out, ECB_CIPHER, ECB_CIPHER_LEN)) {
        puts("Secondary SE Encryption failed");
    }
    else {
        puts("Secondary SE Encryption successful");
    }
}
#endif

int main(void)
{
    psa_crypto_init();

#if IS_ACTIVE(CONFIG_CURVE_ECC_P256)
    example_sign_verify();
#endif
#if IS_ACTIVE(CONFIG_CIPHER_AES_128_CBC)
    example_cipher_aes_cbc();
#endif
#if IS_ACTIVE(CONFIG_PSA_CRYPTO_SECURE_ELEMENT)
    example_prim_se();
#endif
#if IS_ACTIVE(CONFIG_PSA_MULTIPLE_SECURE_ELEMENTS)
    example_sec_se();
#endif
    return 0;
}