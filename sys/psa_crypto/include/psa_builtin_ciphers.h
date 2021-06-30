#ifndef PSA_BUILTIN_CIPHERS_H
#define PSA_BUILTIN_CIPHERS_H

#include "psa/crypto.h"
#include "crypto/ciphers.h"

typedef cipher_context_t psa_builtin_cipher_operation_t;

psa_status_t psa_builtin_cipher_setup(  psa_cipher_operation_t * operation,
                                        psa_key_id_t key,
                                        psa_algorithm_t alg);

psa_status_t psa_builtin_cipher_encrypt(psa_key_id_t key,
                                        psa_algorithm_t alg,
                                        const uint8_t * input,
                                        size_t input_length,
                                        uint8_t * output,
                                        size_t output_size,
                                        size_t * output_length);

psa_status_t psa_builtin_cipher_decrypt(psa_key_id_t key,
                                        psa_algorithm_t alg,
                                        const uint8_t * input,
                                        size_t input_length,
                                        uint8_t * output,
                                        size_t output_size,
                                        size_t * output_length);

#endif /* PSA_BUILTIN_CIPHERS_H */
