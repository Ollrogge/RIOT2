#ifndef PSA_CRYPTO_ALGORITHM_DISPATCHER_H
#define PSA_CRYPTO_ALGORITHM_DISPATCHER_H

#include "psa/crypto.h"
#include "psa_crypto_slot_management.h"

#define PSA_INVALID_OPERATION     (0xFF)

typedef enum {
    PSA_CBC_NO_PAD_AES_128,
    PSA_CBC_NO_PAD_AES_192,
    PSA_CBC_NO_PAD_AES_256,
    PSA_CBC_PKCS7_AES_256
} psa_cipher_op_t;

typedef enum {
    PSA_ECC_P192_R1,
    PSA_ECC_P256_R1,
    PSA_ECC_P384_R1,
    PSA_ECC_P521_R1
} psa_asymmetric_keytype_t;

#define GET_ECC_KEY_TYPE_192(curve) \
            ((curve == PSA_ECC_FAMILY_SECP_R1) ? PSA_ECC_P192_R1 : \
             PSA_INVALID_OPERATION)

#define GET_ECC_KEY_TYPE_256(curve) \
            ((curve == PSA_ECC_FAMILY_SECP_R1) ? PSA_ECC_P256_R1 : \
             PSA_INVALID_OPERATION)

#define PSA_ENCODE_ECC_KEY_TYPE(bits, curve) \
            ((bits == 256) ? GET_ECC_KEY_TYPE_256(curve) : \
             (bits == 192) || (bits == 392) ? GET_ECC_KEY_TYPE_192(curve) : \
             PSA_INVALID_OPERATION)

#define GET_CIPHER_OPERATION_128(alg, type) \
            (((alg == PSA_ALG_CBC_NO_PADDING) && (type == PSA_KEY_TYPE_AES)) ? PSA_CBC_NO_PAD_AES_128 : \
             PSA_INVALID_OPERATION)

#define GET_CIPHER_OPERATION_192(alg, type) \
            (((alg == PSA_ALG_CBC_NO_PADDING) && (type == PSA_KEY_TYPE_AES)) ? PSA_CBC_NO_PAD_AES_192 : \
             PSA_INVALID_OPERATION)

#define GET_CIPHER_OPERATION_256(alg, type) \
            (((alg == PSA_ALG_CBC_NO_PADDING) && (type == PSA_KEY_TYPE_AES)) ? PSA_CBC_NO_PAD_AES_256 : \
            ((alg == PSA_ALG_CBC_PKCS7) && (type == PSA_KEY_TYPE_AES)) ? PSA_CBC_PKCS7_AES_256 : \
             PSA_INVALID_OPERATION)

#define PSA_ENCODE_CIPHER_OPERATION(alg, bits, type) \
            ((bits == 128) ? GET_CIPHER_OPERATION_128(alg, type) : \
             (bits == 192) ? GET_CIPHER_OPERATION_192(alg, type) : \
             (bits == 256) ? GET_CIPHER_OPERATION_256(alg, type) : \
             PSA_INVALID_OPERATION)

#endif /* PSA_CRYPTO_ALGORITHM_DISPATCHER_H */