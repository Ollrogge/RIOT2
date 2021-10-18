
#include "kernel_defines.h"
#include "psa/crypto.h"
#include "include/psa_ciphers.h"

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
#if IS_ACTIVE(CONFIG_PSA_CIPHER_AES_KEY_SIZE_128)
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

psa_status_t psa_cipher_cbc_encrypt(psa_key_slot_t *slot,
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