#include <stdio.h>
#include <stdint.h>

#include "psa/crypto.h"
#include "atca_params.h"

#ifdef TEST_STACK
#include "ps.h"
#endif

#include "xtimer.h"

#define AES_128_KEY_SIZE    (16)
#define ECDSA_MESSAGE_SIZE  (127)
#define ECC_KEY_SIZE    (256)

static const uint8_t KEY_128[] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

static uint8_t PLAINTEXT[] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
};
static uint8_t PLAINTEXT_LEN = 32;
static uint8_t CBC_CIPHER_LEN = 32;

const uint8_t SHA256_MSG[] = {  0x09, 0xfc, 0x1a, 0xcc, 0xc2, 0x30, 0xa2, 0x05,
                                0xe4, 0xa2, 0x08, 0xe6, 0x4a, 0x8f, 0x20, 0x42,
                                0x91, 0xf5, 0x81, 0xa1, 0x27, 0x56, 0x39, 0x2d,
                                0xa4, 0xb8, 0xc0, 0xcf, 0x5e, 0xf0, 0x2b, 0x95};
const size_t SHA256_MSG_LEN = 32;

const uint8_t SHA256_DIG[] = {  0x4f, 0x44, 0xc1, 0xc7, 0xfb, 0xeb, 0xb6, 0xf9,
                                0x60, 0x18, 0x29, 0xf3, 0x89, 0x7b, 0xfd, 0x65,
                                0x0c, 0x56, 0xfa, 0x07, 0x84, 0x4b, 0xe7, 0x64,
                                0x89, 0x07, 0x63, 0x56, 0xac, 0x18, 0x86, 0xa4};
const size_t SHA256_DIG_LEN = 32;

const uint8_t SHA512_MSG[] = {  0x8c, 0xcb, 0x08, 0xd2, 0xa1, 0xa2, 0x82, 0xaa,
                                0x8c, 0xc9, 0x99, 0x02, 0xec, 0xaf, 0x0f, 0x67,
                                0xa9, 0xf2, 0x1c, 0xff, 0xe2, 0x80, 0x05, 0xcb,
                                0x27, 0xfc, 0xf1, 0x29, 0xe9, 0x63, 0xf9, 0x9d};
const size_t SHA512_MSG_LEN = 32;

const uint8_t SHA512_DIG[] = {  0x45, 0x51, 0xde, 0xf2, 0xf9, 0x12, 0x73, 0x86,
                                0xee, 0xa8, 0xd4, 0xda, 0xe1, 0xea, 0x8d, 0x8e,
                                0x49, 0xb2, 0xad, 0xd0, 0x50, 0x9f, 0x27, 0xcc,
                                0xbc, 0xe7, 0xd9, 0xe9, 0x50, 0xac, 0x7d, 0xb0,
                                0x1d, 0x5b, 0xca, 0x57, 0x9c, 0x27, 0x1b, 0x9f,
                                0x2d, 0x80, 0x67, 0x30, 0xd8, 0x8f, 0x58, 0x25,
                                0x2f, 0xd0, 0xc2, 0x58, 0x78, 0x51, 0xc3, 0xac,
                                0x8a, 0x0e, 0x72, 0xb4, 0xe1, 0xdc, 0x0d, 0xa6};
const size_t SHA512_DIG_LEN = 64;

static void cipher_aes_128(void)
{
    psa_status_t status = PSA_ERROR_DOES_NOT_EXIST;

    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_key_id_t key_id = 0;
    psa_key_usage_t usage = PSA_KEY_USAGE_ENCRYPT;

    size_t iv_size = PSA_CIPHER_IV_LENGTH(PSA_KEY_TYPE_AES, PSA_ALG_CBC_NO_PADDING);
    size_t combined_output_size = CBC_CIPHER_LEN + iv_size;

    uint8_t cipher_out[combined_output_size];
    size_t output_len = 0;

    psa_set_key_algorithm(&attr, PSA_ALG_CBC_NO_PADDING);
    psa_set_key_usage_flags(&attr, usage);
    psa_set_key_bits(&attr, 128);
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);

    status = psa_import_key(&attr, KEY_128, AES_128_KEY_SIZE, &key_id);
    if (status != PSA_SUCCESS) {
        printf("AES 128 Key Import failed: %ld\n", status);
        return;
    }

    status = psa_cipher_encrypt(key_id, PSA_ALG_CBC_NO_PADDING, PLAINTEXT, PLAINTEXT_LEN, cipher_out, combined_output_size, &output_len);
    if (status != PSA_SUCCESS) {
        printf("AES 128 CBC Encrypt failed: %ld\n", status);
        return;
    }
    puts("AES 128 CBC Success");
}

static void hashes_sha256(void)
{
    psa_status_t status = PSA_ERROR_DOES_NOT_EXIST;
    uint8_t result[SHA256_DIG_LEN];
    size_t hash_length;

    status = psa_hash_compute(PSA_ALG_SHA_256, SHA256_MSG, SHA256_MSG_LEN, result, sizeof(result), &hash_length);
    if (status != PSA_SUCCESS || hash_length != SHA256_DIG_LEN) {
        printf("SHA 256 failed: %ld\n", status);
        return;
    }
    puts("SHA 256 Success");
}

static void ecdsa_prim_se(void)
{
    psa_status_t status = PSA_ERROR_DOES_NOT_EXIST;

    psa_key_id_t privkey_id;
    psa_key_attributes_t privkey_attr = psa_key_attributes_init();

    psa_key_lifetime_t lifetime = PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(PSA_KEY_LIFETIME_VOLATILE, PSA_ATCA_LOCATION_DEV0);
    psa_key_usage_t usage = PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH;
    psa_key_type_t type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
    psa_algorithm_t alg =  PSA_ALG_ECDSA(PSA_ALG_SHA_256);
    psa_key_bits_t bits = ECC_KEY_SIZE;

    uint8_t signature[PSA_SIGN_OUTPUT_SIZE(type, bits, alg)];
    size_t sig_length;
    uint8_t msg[ECDSA_MESSAGE_SIZE] = { 0x0b };
    uint8_t hash[PSA_HASH_LENGTH(PSA_ALG_SHA_256)];
    size_t hash_length;

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
    status = psa_hash_compute(PSA_ALG_SHA_256, msg, sizeof(msg), hash, sizeof(hash), &hash_length);
    if (status != PSA_SUCCESS) {
        printf("Hash Generation failed: %ld\n", status);
        return;
    }

    status = psa_sign_hash(privkey_id, alg, hash, sizeof(hash), signature, sizeof(signature), &sig_length);
    if (status != PSA_SUCCESS) {
        printf("Primary SE Sign hash failed: %ld\n", status);
        return;
    }


    status = psa_verify_hash(privkey_id, alg, hash, sizeof(hash), signature, sig_length);
    if (status != PSA_SUCCESS) {
        printf("Primary SE Verify hash failed: %ld\n", status);
        return;
    }

    puts("ECDSA Primary SE Success");
}

static void ecdsa_sec_se(void)
{
    psa_status_t status = PSA_ERROR_DOES_NOT_EXIST;

    psa_key_id_t privkey_id;
    psa_key_attributes_t privkey_attr = psa_key_attributes_init();
    psa_key_id_t pubkey_id;
    psa_key_attributes_t pubkey_attr = psa_key_attributes_init();

    psa_key_lifetime_t lifetime = PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(PSA_KEY_LIFETIME_VOLATILE, PSA_ATCA_LOCATION_DEV1);
    psa_key_usage_t usage = PSA_KEY_USAGE_SIGN_HASH;
    psa_key_type_t type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
    psa_algorithm_t alg =  PSA_ALG_ECDSA(PSA_ALG_SHA_256);
    psa_key_bits_t bits = ECC_KEY_SIZE;

    uint8_t public_key[PSA_EXPORT_PUBLIC_KEY_MAX_SIZE] = { 0 };
    size_t pubkey_length;

    uint8_t signature[PSA_SIGN_OUTPUT_SIZE(type, bits, alg)];
    size_t sig_length;
    uint8_t msg[ECDSA_MESSAGE_SIZE] = { 0x0b };
    uint8_t hash[PSA_HASH_LENGTH(PSA_ALG_SHA_256)];
    size_t hash_length;

    psa_set_key_lifetime(&privkey_attr, lifetime);
    psa_set_key_algorithm(&privkey_attr, alg);
    psa_set_key_usage_flags(&privkey_attr, usage);
    psa_set_key_type(&privkey_attr, type);
    psa_set_key_bits(&privkey_attr, bits);

    status = psa_generate_key(&privkey_attr, &privkey_id);
    if (status != PSA_SUCCESS) {
        printf("Secondary SE Generate Key failed: %ld\n", status);
        return;
    }

    status = psa_export_public_key(privkey_id, public_key, sizeof(public_key), &pubkey_length);
    if (status != PSA_SUCCESS) {
        printf("Secondary SE Export Public Key failed: %ld\n", status);
        return;
    }

    psa_set_key_lifetime(&pubkey_attr, lifetime);
    psa_set_key_algorithm(&pubkey_attr, alg);
    psa_set_key_usage_flags(&pubkey_attr, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_bits(&pubkey_attr, PSA_BYTES_TO_BITS(PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(type, bits)));
    psa_set_key_type(&pubkey_attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));

    status = psa_import_key(&pubkey_attr, public_key, pubkey_length, &pubkey_id);
    if (status != PSA_SUCCESS) {
        printf("PSA Import Public Key failed: %ld\n", status);
        return;
    }

    status = psa_hash_compute(PSA_ALG_SHA_256, msg, sizeof(msg), hash, sizeof(hash), &hash_length);
    if (status != PSA_SUCCESS) {
        printf("Hash Generation failed: %ld\n", status);
        return;
    }

    status = psa_sign_hash(privkey_id, alg, hash, sizeof(hash), signature, sizeof(signature), &sig_length);
    if (status != PSA_SUCCESS) {
        printf("Secondary SE Sign hash failed: %ld\n", status);
        return;
    }

    status = psa_verify_hash(pubkey_id, alg, hash, sizeof(hash), signature, sig_length);
    if (status != PSA_SUCCESS) {
        printf("Secondary SE Verify hash failed: %ld\n", status);
        return;
    }

    puts("ECDSA Secondary SE Success");
}

void ecdsa_cc(void)
{
    psa_status_t status = PSA_ERROR_DOES_NOT_EXIST;

    psa_key_id_t privkey_id;
    psa_key_attributes_t privkey_attr = psa_key_attributes_init();

    psa_key_usage_t usage = PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH;
    psa_key_type_t type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
    psa_algorithm_t alg =  PSA_ALG_ECDSA(PSA_ALG_SHA_256);
    psa_key_bits_t bits = ECC_KEY_SIZE;

    uint8_t signature[PSA_SIGN_OUTPUT_SIZE(type, bits, alg)];
    size_t sig_length;
    uint8_t msg[ECDSA_MESSAGE_SIZE] = { 0x0b };
    uint8_t hash[PSA_HASH_LENGTH(PSA_ALG_SHA_256)];
    size_t hash_length;

    psa_set_key_algorithm(&privkey_attr, alg);
    psa_set_key_usage_flags(&privkey_attr, usage);
    psa_set_key_type(&privkey_attr, type);
    psa_set_key_bits(&privkey_attr, bits);

    status = psa_generate_key(&privkey_attr, &privkey_id);
    if (status != PSA_SUCCESS) {
        printf("Local Generate Key failed: %ld\n", status);
        return;
    }

    status = psa_hash_compute(PSA_ALG_SHA_256, msg, sizeof(msg), hash, sizeof(hash), &hash_length);
    if (status != PSA_SUCCESS) {
        printf("Hash Generation failed: %ld\n", status);
        return;
    }

    status = psa_sign_hash(privkey_id, alg, hash, sizeof(hash), signature, sizeof(signature), &sig_length);
    if (status != PSA_SUCCESS) {
        printf("Periph Sign hash failed: %ld\n", status);
        return;
    }

    status = psa_verify_hash(privkey_id, alg, hash, sizeof(hash), signature, sig_length);
    if (status != PSA_SUCCESS) {
        printf("Periph Verify hash failed: %ld\n", status);
        return;
    }

    puts("ECDSA Periph Success");
}

int main(void)
{
    psa_crypto_init();
    cipher_aes_128();
    // cipher_aes_256();
    hashes_sha256();
    // hashes_sha512();
    ecdsa_prim_se();
    ecdsa_sec_se();
    ecdsa_cc();
    return 0;
}