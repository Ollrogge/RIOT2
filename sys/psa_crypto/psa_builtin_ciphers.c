#include "psa_builtin_ciphers.h"

psa_status_t psa_builtin_cipher_setup(  psa_cipher_operation_t * operation,
                                        psa_key_id_t key,
                                        psa_algorithm_t alg)
{

}

psa_status_t psa_builtin_cipher_encrypt(psa_key_id_t key,
                                        psa_algorithm_t alg,
                                        const uint8_t * input,
                                        size_t input_length,
                                        uint8_t * output,
                                        size_t output_size,
                                        size_t * output_length)
{

}

psa_status_t psa_builtin_cipher_decrypt(psa_key_id_t key,
                                        psa_algorithm_t alg,
                                        const uint8_t * input,
                                        size_t input_length,
                                        uint8_t * output,
                                        size_t output_size,
                                        size_t * output_length)
{

}