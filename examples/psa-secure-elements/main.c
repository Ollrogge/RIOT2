#include <stdio.h>
#include <stdint.h>

#include "psa/crypto.h"
#include "atca_params.h"

#define ECDSA_MESSAGE_SIZE  (127)
#define ECC_CURVE_BITS      (256)
#define AES_128_KEY_SIZE    (16)
#define AES_CIPHER_LEN      (32)

static uint8_t PLAINTEXT[] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
};
static uint8_t PLAINTEXT_LEN = 32;

psa_key_id_t privkey_id;
psa_key_attributes_t privkey_attr;
psa_key_id_t pubkey_id;
psa_key_attributes_t pubkey_attr;

psa_key_lifetime_t lifetime = PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(PSA_KEY_LIFETIME_VOLATILE, PSA_ATCA_LOCATION_DEV0);
psa_key_usage_t usage = PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH;
psa_key_type_t type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
psa_algorithm_t alg =  PSA_ALG_ECDSA(PSA_ALG_SHA_256);
psa_key_bits_t bits = ECC_CURVE_BITS;


static void aes_ecb_prim_se(void)
{
    psa_status_t status = PSA_ERROR_DOES_NOT_EXIST;

    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_key_id_t key_id = 0;
    psa_key_usage_t usage = PSA_KEY_USAGE_ENCRYPT;
    psa_key_lifetime_t lifetime = PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(PSA_KEY_LIFETIME_VOLATILE, PSA_ATCA_LOCATION_DEV0);

    uint8_t cipher_out[AES_CIPHER_LEN];
    size_t output_len = 0;

    psa_set_key_lifetime(&attr, lifetime);
    psa_set_key_algorithm(&attr, PSA_ALG_ECB_NO_PADDING);
    psa_set_key_usage_flags(&attr, usage);
    psa_set_key_bits(&attr, PSA_BYTES_TO_BITS(AES_128_KEY_SIZE));
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);

    status = psa_generate_key(&attr, &key_id);
    if (status != PSA_SUCCESS) {
        printf("AES 128 Key Generation failed: %ld\n", status);
        return;
    }

    status = psa_cipher_encrypt(key_id, PSA_ALG_ECB_NO_PADDING, PLAINTEXT, PLAINTEXT_LEN, cipher_out, AES_CIPHER_LEN, &output_len);
    if (status != PSA_SUCCESS || output_len != AES_CIPHER_LEN) {
        printf("AES 128 ECB Encrypt failed: %ld\nOutput Length: %d\n", status, output_len);
        return;
    }
    puts("AES 128 ECB Success");
}

static void ecdsa_prim_se(void)
{
    psa_status_t status = PSA_ERROR_DOES_NOT_EXIST;

    uint8_t public_key[PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), ECC_CURVE_BITS)] = { 0 };
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

    /* Generate a key pair. This stores both the reference to the private key and the public key
    in the same key slot and returns the key identifier which can be used to access those keys */

    for (int i= 0; i < 4; i++) {
        status = psa_generate_key(&privkey_attr, &privkey_id);
        if (status != PSA_SUCCESS) {
            printf("Primary SE Generate Key failed: %ld\n", status);
            return;
        }
    }

    /* Export public key from the stored key pair. This implementation only supports the use of secure elements, when keys are stored on the device. This means that public keys need to be imported to another slot on the SE. */
    status = psa_export_public_key(privkey_id, public_key, sizeof(public_key), &pubkey_length);
    if (status != PSA_SUCCESS) {
        printf("Primary SE Export Public Key failed: %ld\n", status);
        return;
    }

    uint8_t bytes = PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1),bits);

    psa_set_key_lifetime(&pubkey_attr, lifetime);
    psa_set_key_algorithm(&pubkey_attr, alg);
    psa_set_key_usage_flags(&pubkey_attr, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_bits(&pubkey_attr, PSA_BYTES_TO_BITS(bytes));
    psa_set_key_type(&pubkey_attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));

    status = psa_import_key(&pubkey_attr, public_key, pubkey_length, &pubkey_id);
    if (status != PSA_SUCCESS) {
        printf("PSA Import Public Key failed: %ld\n", status);
        return;
    }

    /* The message must be hashed before performing the signature (the psa_sign_message funtion is
    not implemented, yet, so we have to do this manually). */
    status = psa_hash_compute(PSA_ALG_SHA_256, msg, sizeof(msg), hash, sizeof(hash), &hash_length);
    if (status != PSA_SUCCESS) {
        printf("Hash Generation failed: %ld\n", status);
        return;
    }

    /* Perform sign and verify operations using the same key identifier. Psa_sign_hash uses the private key stored on the SE. Psa_verify_hash uses the public key stored locally. */
    status = psa_sign_hash(privkey_id, alg, hash, sizeof(hash), signature, sizeof(signature), &sig_length);
    if (status != PSA_SUCCESS) {
        printf("Primary SE Sign hash failed: %ld\n", status);
        return;
    }

    status = psa_verify_hash(pubkey_id, alg, hash, sizeof(hash), signature, sig_length);
    if (status != PSA_SUCCESS) {
        printf("Primary SE Verify hash failed: %ld\n", status);
        return;
    }

    puts("ECDSA Primary SE Success");
}

#ifdef MULTIPLE_BACKENDS
static void ecdsa_sec_se(void)
{
    psa_status_t status = PSA_ERROR_DOES_NOT_EXIST;

    uint8_t public_key[PSA_EXPORT_PUBLIC_KEY_MAX_SIZE] = { 0 };
    size_t pubkey_length;

    uint8_t signature[PSA_SIGN_OUTPUT_SIZE(type, bits, alg)];
    size_t sig_length;
    uint8_t msg[ECDSA_MESSAGE_SIZE] = { 0x0b };
    uint8_t hash[PSA_HASH_LENGTH(PSA_ALG_SHA_256)];
    size_t hash_length;

    lifetime = PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(PSA_KEY_LIFETIME_VOLATILE, PSA_ATCA_LOCATION_DEV1);

    /* Export public key from the stored key pair. This does not recalculate the public key, but uses the one that got stored locally after generating the key pair in the step before.*/
    status = psa_export_public_key(privkey_id, public_key, sizeof(public_key), &pubkey_length);
    if (status != PSA_SUCCESS) {
        printf("Secondary SE Export Public Key failed: %ld\n", status);
        return;
    }

    /* Set attributes for public key import */
    uint8_t bytes = PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1),bits);

    psa_set_key_lifetime(&pubkey_attr, lifetime);
    psa_set_key_algorithm(&pubkey_attr, alg);
    psa_set_key_usage_flags(&pubkey_attr, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_bits(&pubkey_attr, PSA_BYTES_TO_BITS(bytes));
    psa_set_key_type(&pubkey_attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));

    /* Import the previously exported public key to a slot on a secure element. The reference to the public key will be stored with a separate key identifier. */
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

    /* Perform the ECDSA operation. Psa_sign_hash uses the private key stored on the SE. Psa_verify_hash uses the public key stored on the SE */
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
#endif

int main(void)
{
    psa_crypto_init();

    privkey_attr = psa_key_attributes_init();
    pubkey_attr = psa_key_attributes_init();

    aes_ecb_prim_se();
    ecdsa_prim_se();
#ifdef MULTIPLE_BACKENDS
    ecdsa_sec_se();
#endif
    return 0;
}