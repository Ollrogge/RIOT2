
#include "kernel_defines.h"
#include "psa/crypto.h"
#include "include/psa_ciphers.h"
#include "include/psa_crypto_slot_management.h"
#include "include/psa_crypto_algorithm_dispatcher.h"

static psa_status_t psa_cipher_cbc_encrypt( const psa_key_attributes_t *attributes,
                                            const uint8_t *key_buffer,
                                            size_t key_buffer_size,
                                            psa_algorithm_t alg,
                                            const uint8_t * input,
                                            size_t input_length,
                                            uint8_t * output,
                                            size_t output_size,
                                            size_t * output_length)
{
    psa_cipher_key_type_t cipher_key = PSA_ENCODE_CIPHER_KEY_TYPE(attributes->bits, attributes->type);

    if (cipher_key == PSA_INVALID_KEY) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    switch(cipher_key) {
#if IS_ACTIVE(CONFIG_PSA_CIPHER_AES_KEY_SIZE_128)
        case PSA_KEY_AES_128:
            return psa_cipher_cbc_aes_128_encrypt(attributes, key_buffer, key_buffer_size, alg, input, input_length, output, output_size, output_length);
#endif
#if IS_ACTIVE(CONFIG_PSA_CIPHER_AES_KEY_SIZE_192)
        case PSA_KEY_AES_192:
            return psa_cipher_cbc_aes_192_encrypt(attributes, key_buffer, key_buffer_size, alg, input, input_length, output, output_size, output_length);
#endif
#if IS_ACTIVE(CONFIG_PSA_CIPHER_AES_KEY_SIZE_256)
        case PSA_KEY_AES_256:
            return psa_cipher_cbc_aes_256_encrypt(attributes, key_buffer, key_buffer_size, alg, input, input_length, output, output_size, output_length);
#endif
        default:
            (void) attributes;
            (void) key_buffer;
            (void) key_buffer_size;
            (void) input;
            (void) input_length;
            (void) output;
            (void) output_size;
            (void) output_length;
            return PSA_ERROR_NOT_SUPPORTED;
    }
}

psa_status_t psa_cipher_encrypt_dispatch(   psa_key_slot_t *slot,
                                            psa_algorithm_t alg,
                                            const uint8_t * input,
                                            size_t input_length,
                                            uint8_t * output,
                                            size_t output_size,
                                            size_t * output_length)
{
    psa_key_attributes_t attributes = slot->attr;

    switch(alg) {
#if IS_ACTIVE(CONFIG_PSA_CIPHER_MODE_CBC)
        case PSA_ALG_CBC_NO_PADDING:
        case PSA_ALG_CBC_PKCS7:
            return psa_cipher_cbc_encrypt(&attributes, slot->key.data, slot->key.bytes, alg, input, input_length, output, output_size, output_length);
#endif
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

psa_status_t psa_generate_asymmetric_key_pair_dispatch( const psa_key_attributes_t *attributes,
                                                        uint8_t *key_buffer, size_t key_buffer_size,
                                                        size_t *key_buffer_length)
{
    psa_asymmetric_key_type_t asym_key = PSA_INVALID_KEY;

    if (PSA_KEY_TYPE_IS_ECC_KEY_PAIR(attributes->type)) {
        asym_key = PSA_ENCODE_ECC_KEY_TYPE(attributes->bits, PSA_KEY_TYPE_ECC_GET_CURVE(attributes->type));
    }

    if (asym_key == PSA_INVALID_KEY) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    switch(asym_key) {
#if IS_ACTIVE(CONFIG_PSA_CURVE_ECC_KEY_SIZE_256)
        case PSA_ECC_SECP_R1_256:
            return psa_generate_ecc_secp_r1_256_key_pair(attributes, key_buffer, key_buffer_size, key_buffer_length);
#endif
        default:
        (void) key_buffer;
        (void) key_buffer_size;
        (void) key_buffer_length;
        return PSA_ERROR_NOT_SUPPORTED;
    }
}