#ifndef PSA_ECC_H
#define PSA_ECC_H

#include "psa/crypto.h"
#include "kernel_defines.h"

psa_status_t psa_generate_ecc_p192r1_key_pair(  const psa_key_attributes_t *attributes,
                                                uint8_t * priv_key_buffer, uint8_t * pub_key_buffer, size_t *priv_key_buffer_length, size_t *pub_key_buffer_length);

psa_status_t psa_ecc_p192r1_export_public_key(  const psa_key_attributes_t *attributes,
                                                uint8_t *key_buffer,
                                                size_t key_buffer_size,
                                                uint8_t * data,
                                                size_t data_size,
                                                size_t * data_length);

psa_status_t psa_ecc_p192r1_sign_hash(  const psa_key_attributes_t *attributes,
                                        psa_algorithm_t alg,
                                        const uint8_t *key_buffer, size_t key_buffer_size,
                                        const uint8_t *hash, size_t hash_length,
                                        uint8_t * signature, size_t signature_size,
                                        size_t * signature_length);

psa_status_t psa_ecc_p192r1_verify_hash(const psa_key_attributes_t *attributes,
                                        psa_algorithm_t alg,
                                        const uint8_t *key_buffer, size_t key_buffer_size,
                                        const uint8_t *hash, size_t hash_length,
                                        const uint8_t *signature, size_t signature_length);

psa_status_t psa_generate_ecc_p256r1_key_pair(  const psa_key_attributes_t *attributes,
                                                uint8_t * priv_key_buffer, uint8_t * pub_key_buffer, size_t *priv_key_buffer_length, size_t *pub_key_buffer_length);

psa_status_t psa_ecc_p256r1_export_public_key(  const psa_key_attributes_t *attributes,
                                                uint8_t *key_buffer,
                                                size_t key_buffer_size,
                                                uint8_t * data,
                                                size_t data_size,
                                                size_t * data_length);

psa_status_t psa_ecc_p256r1_sign_hash(  const psa_key_attributes_t *attributes,
                                        psa_algorithm_t alg,
                                        const uint8_t *key_buffer, size_t key_buffer_size,
                                        const uint8_t *hash, size_t hash_length,
                                        uint8_t * signature, size_t signature_size,
                                        size_t * signature_length);

psa_status_t psa_ecc_p256r1_verify_hash(const psa_key_attributes_t *attributes,
                                        psa_algorithm_t alg,
                                        const uint8_t *key_buffer, size_t key_buffer_size,
                                        const uint8_t *hash, size_t hash_length,
                                        const uint8_t *signature, size_t signature_length);

#endif /* PSA_ECC_H */