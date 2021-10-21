#ifndef PSA_CRYPTO_ALGORITHM_DISPATCHER_H
#define PSA_CRYPTO_ALGORITHM_DISPATCHER_H

#include "psa/crypto.h"
#include "psa_crypto_slot_management.h"

#define PSA_INVALID_KEY     (0xFF)

typedef enum {
    PSA_KEY_AES_128,
    PSA_KEY_AES_192,
    PSA_KEY_AES_256
} psa_cipher_key_type_t;

typedef enum {
    PSA_ECC_SECP_R1_256,
    PSA_ECC_SECP_R1_384,
    PSA_ECC_SECP_R1_521
} psa_asymmetric_key_type_t;

#define GET_ECC_KEY_TYPE_256(curve) \
            ((curve == PSA_ECC_FAMILY_SECP_R1) ? PSA_ECC_SECP_R1_256 : \
             PSA_INVALID_KEY)

#define PSA_ENCODE_ECC_KEY_TYPE(bits, curve) \
            ((bits == 256) ? GET_ECC_KEY_TYPE_256(curve) : \
             PSA_INVALID_KEY)

#define GET_CIPHER_KEY_TYPE_128(type) \
            ((type == PSA_KEY_TYPE_AES) ? PSA_KEY_AES_128 : \
             PSA_INVALID_KEY)

#define GET_CIPHER_KEY_TYPE_192(type) \
            ((type == PSA_KEY_TYPE_AES) ? PSA_KEY_AES_192 : \
             PSA_INVALID_KEY)

#define GET_CIPHER_KEY_TYPE_256(type) \
            ((type == PSA_KEY_TYPE_AES) ? PSA_KEY_AES_256 : \
             PSA_INVALID_KEY)

#define PSA_ENCODE_CIPHER_KEY_TYPE(bits, type) \
            ((bits == 128) ? GET_CIPHER_KEY_TYPE_128(type) : \
             (bits == 192) ? GET_CIPHER_KEY_TYPE_192(type) : \
             (bits == 256) ? GET_CIPHER_KEY_TYPE_256(type) : \
             PSA_INVALID_KEY)

psa_status_t psa_cipher_encrypt_dispatch(   psa_key_slot_t *slot,
                                            psa_algorithm_t alg,
                                            const uint8_t * input,
                                            size_t input_length,
                                            uint8_t * output,
                                            size_t output_size,
                                            size_t * output_length);

psa_status_t psa_generate_asymmetric_key_pair_dispatch( const psa_key_attributes_t *attributes,
                                                        uint8_t *key_buffer, size_t key_buffer_size,
                                                        size_t *key_buffer_length);

#endif /* PSA_CRYPTO_ALGORITHM_DISPATCHER_H */