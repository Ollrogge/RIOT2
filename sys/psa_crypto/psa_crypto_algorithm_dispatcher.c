
#include "kernel_defines.h"
#include "psa/crypto.h"
#include "include/psa_ciphers.h"
#include "include/psa_crypto_slot_management.h"

static psa_status_t psa_cipher_cbc_aes_encrypt( const psa_key_attributes_t *attributes,
                                                const uint8_t *key_buffer,
                                                size_t key_buffer_size,
                                                psa_algorithm_t alg,
                                                const uint8_t * input,
                                                size_t input_length,
                                                uint8_t * output,
                                                size_t output_size,
                                                size_t * output_length)
{
    switch(psa_get_key_bits(attributes)) {
#if IS_ACTIVE(CONFIG_PSA_CIPHER_AES_KEY_SIZE_128)
        case 128:
            return psa_cipher_cbc_aes_128_encrypt(attributes, key_buffer, key_buffer_size, alg, input, input_length, output, output_size, output_length);
#endif
#if IS_ACTIVE(CONFIG_PSA_CIPHER_AES_KEY_SIZE_192)
        case 192:
            return psa_cipher_cbc_aes_192_encrypt(attributes, key_buffer, key_buffer_size, alg, input, input_length, output, output_size, output_length);
#endif
#if IS_ACTIVE(CONFIG_PSA_CIPHER_AES_KEY_SIZE_256)
        case 256:
            return psa_cipher_cbc_aes_256_encrypt(attributes, key_buffer, key_buffer_size, alg, input, input_length, output, output_size, output_length);
#endif
        default:
            (void) key_buffer;
            (void) key_buffer_size;
            (void) alg;
            (void) input;
            (void) input_length;
            (void) output;
            (void) output_size;
            (void) output_length;
            return PSA_ERROR_NOT_SUPPORTED;
    }
}

psa_status_t psa_cipher_dispatch_encrypt(   psa_key_slot_t *slot,
                                            psa_algorithm_t alg,
                                            const uint8_t * input,
                                            size_t input_length,
                                            uint8_t * output,
                                            size_t output_size,
                                            size_t * output_length)
{
    psa_key_attributes_t attributes = slot->attr;

    switch(attributes.type) {
        case PSA_KEY_TYPE_AES:
            return psa_cipher_cbc_aes_encrypt(&attributes, slot->key.data, slot->key.bytes, alg, input, input_length, output, output_size, output_length);
        default:
            (void) slot;
            (void) input;
            (void) input_length;
            (void) output;
            (void) output_size;
            (void) output_length;
            return PSA_ERROR_NOT_SUPPORTED;
    }
}

static psa_status_t psa_generate_ecc_key_pair(  const psa_key_attributes_t *attributes,
                                                uint8_t *key_buffer, size_t key_buffer_size,
                                                size_t *key_buffer_length)
{
    psa_ecc_family_t curve = PSA_KEY_TYPE_ECC_GET_CURVE(attributes->type);

    switch(curve) {
        case PSA_ECC_FAMILY_SECP_R1:
            return psa_generate_ecc_secp_r1_key_pair(attributes, key_buffer, key_buffer_size, key_buffer_length);
        default:
            return PSA_ERROR_NOT_SUPPORTED;
    }
}

psa_status_t psa_generate_asymmetric_key_pair(  const psa_key_attributes_t *attributes,
                                                uint8_t *key_buffer, size_t key_buffer_size,
                                                size_t *key_buffer_length)
{
    if (PSA_KEY_TYPE_IS_ECC_KEY_PAIR(attributes->type)) {
        return psa_generate_ecc_key_pair(attributes, key_buffer, key_buffer_size, key_buffer_length);
    }
    return PSA_ERROR_NOT_SUPPORTED;
}