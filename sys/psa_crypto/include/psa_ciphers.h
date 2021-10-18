#ifndef PSA_CIPHERS_H
#define PSA_CIPHERS_H

#include "psa/crypto.h"
#include "psa/crypto_contexts.h"

psa_status_t psa_cipher_cbc_aes_128_encrypt(const psa_key_attributes_t *attributes,
                                            const uint8_t *key_buffer,
                                            size_t key_buffer_size,
                                            psa_algorithm_t alg,
                                            const uint8_t * input,
                                            size_t input_length,
                                            uint8_t * output,
                                            size_t output_size,
                                            size_t * output_length);

psa_status_t psa_cipher_cbc_aes_192_encrypt(const psa_key_attributes_t *attributes,
                                            const uint8_t *key_buffer,
                                            size_t key_buffer_size,
                                            psa_algorithm_t alg,
                                            const uint8_t * input,
                                            size_t input_length,
                                            uint8_t * output,
                                            size_t output_size,
                                            size_t * output_length);

psa_status_t psa_cipher_cbc_aes_256_encrypt(const psa_key_attributes_t *attributes,
                                            const uint8_t *key_buffer,
                                            size_t key_buffer_size,
                                            psa_algorithm_t alg,
                                            const uint8_t * input,
                                            size_t input_length,
                                            uint8_t * output,
                                            size_t output_size,
                                            size_t * output_length);

#endif /* PSA_CIPHERS_H */
