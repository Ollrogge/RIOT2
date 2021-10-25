#include <stdio.h>
#include <stdint.h>

#include "psa/crypto.h"

#ifdef TEST_STACK
#include "ps.h"
#endif

static void ecdsa_periph(void)
{
    psa_status_t status = PSA_ERROR_DOES_NOT_EXIST;

    psa_key_id_t privkey_id;
    psa_key_attributes_t privkey_attr = psa_key_attributes_init();
    psa_key_id_t pubkey_id;
    psa_key_attributes_t pubkey_attr = psa_key_attributes_init();

    psa_key_usage_t usage = PSA_KEY_USAGE_SIGN_HASH;
    psa_key_type_t type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
    psa_algorithm_t alg =  PSA_ALG_ECDSA(PSA_ALG_SHA_256);
    psa_key_bits_t bits = PSA_VENDOR_ECC_MAX_CURVE_BITS;

    uint8_t public_key[PSA_EXPORT_PUBLIC_KEY_MAX_SIZE] = { 0 };
    size_t pubkey_length;

    uint8_t signature[PSA_SIGN_OUTPUT_SIZE(type, bits, alg)];
    size_t sig_length;
    uint8_t msg[PSA_HASH_LENGTH(PSA_ALG_SHA_256)] = { 0x0b };

    psa_set_key_algorithm(&privkey_attr, alg);
    psa_set_key_usage_flags(&privkey_attr, usage);
    psa_set_key_type(&privkey_attr, type);
    psa_set_key_bits(&privkey_attr, bits);

    status = psa_generate_key(&privkey_attr, &privkey_id);
    if (status != PSA_SUCCESS) {
        printf("Local Generate Key failed: %ld\n", status);
        return;
    }

    status = psa_export_public_key(privkey_id, public_key, sizeof(public_key), &pubkey_length);
    if (status != PSA_SUCCESS) {
        printf("Local Export Public Key failed: %ld\n", status);
        return;
    }

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
        printf("Periph Sign hash failed: %ld\n", status);
        return;
    }

    status = psa_verify_hash(pubkey_id, alg, msg, sizeof(msg), signature, sig_length);
    if (status != PSA_SUCCESS) {
        printf("Periph Verify hash failed: %ld\n", status);
        return;
    }

    puts("ECDSA Periph Success");
}

int main(void)
{
    ecdsa_periph();
#ifdef MULTIPLE_BACKENDS
#endif

#ifdef TEST_STACK
    ps();
#endif
    return 0;
}
