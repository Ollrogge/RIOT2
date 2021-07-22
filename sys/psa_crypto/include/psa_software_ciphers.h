#ifndef PSA_BUILTIN_CIPHERS_H
#define PSA_BUILTIN_CIPHERS_H

#include "psa/crypto_builtin_contexts.h"

psa_status_t psa_software_cipher_encrypt_setup(  psa_software_cipher_operation_t * operation,
                                                const psa_key_attributes_t *attributes,
                                                const uint8_t *key_buffer,
                                                size_t key_buffer_size,
                                                psa_algorithm_t alg);

psa_status_t psa_software_cipher_decrypt_setup(  psa_software_cipher_operation_t * operation,
                                                const psa_key_attributes_t *attributes,
                                                const uint8_t *key_buffer,
                                                size_t key_buffer_size,
                                                psa_algorithm_t alg);

psa_status_t psa_software_cipher_encrypt(psa_software_cipher_operation_t * operation,
                                        const uint8_t * input,
                                        size_t input_length,
                                        uint8_t * output,
                                        size_t output_size,
                                        size_t * output_length);

#endif /* PSA_BUILTIN_CIPHERS_H */
