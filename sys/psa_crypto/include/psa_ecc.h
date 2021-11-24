#ifndef PSA_ECC_H
#define PSA_ECC_H

#include "psa/crypto.h"
#include "kernel_defines.h"

/**
 * @brief Structure to hold an ECC public key or a reference to an ECC public key
 *
 * When is_plain_key == 0, the key is stored in protected memory and pub_key_data
 * contains a slot number. This is the default value, as all key slots are initialized with 0.
 *
 * When is_plain_key == 1, pub_key_data contains an actual key.
 */
typedef struct {
    uint8_t data[PSA_EXPORT_PUBLIC_KEY_MAX_SIZE];
    uint8_t is_plain_key;
    size_t bytes;
} psa_ecc_pub_key_t;

/**
 * @brief Structure to hold an ECC private and public key pair.
 *
 * priv_key_data contains either an actual private key, when key is stored locally,
 * or a slot number referencing to an actual key in protected memory.
 *
 * The structure holds a psa_ecc_pub_key_t struct, which contains the actual public key,
 * if it's returned by the driver in use. Otherwise this structure stays empty.
 */
typedef struct {
    uint8_t priv_key_data[PSA_MAX_ECC_PRIV_KEY_SIZE]; /*!< Contains private key or, in case of SE, slot number of private key */
    psa_ecc_pub_key_t pub_key; /*!< Contains public key material */
} psa_ecc_keypair_t;

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

#endif /* PSA_ECC_H */