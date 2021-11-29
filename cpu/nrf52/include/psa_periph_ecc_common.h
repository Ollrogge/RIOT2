#ifndef PSA_PERIPH_ECC_COMMON_H
#define PSA_PERIPH_ECC_COMMON_H

#include "psa/crypto.h"

#include "cryptocell_incl/sns_silib.h"
#include "cryptocell_incl/crys_ecpki_build.h"
#include "cryptocell_incl/crys_ecpki_ecdsa.h"
#include "cryptocell_incl/crys_ecpki_kg.h"
#include "cryptocell_incl/crys_ecpki_domain.h"

#define MAP_PSA_HASH_TO_CRYS_HASH(hash) \
        ((hash == PSA_ALG_SHA_1) ? CRYS_ECPKI_AFTER_HASH_SHA1_mode : \
         (hash == PSA_ALG_SHA_224) ? CRYS_ECPKI_AFTER_HASH_SHA224_mode : \
         (hash == PSA_ALG_SHA_256) ? CRYS_ECPKI_AFTER_HASH_SHA256_mode : \
         (hash == PSA_ALG_SHA_384) ? CRYS_ECPKI_AFTER_HASH_SHA384_mode : \
         (hash == PSA_ALG_SHA_512) ? CRYS_ECPKI_AFTER_HASH_SHA512_mode : \
         0)

psa_status_t periph_common_ecc_generate_key_pair(uint8_t * priv_key_buffer,
                                                 uint8_t * pub_key_buffer,
                                                 uint32_t * priv_key_buffer_length,
                                                 uint32_t * pub_key_buffer_length,
                                                 CRYS_ECPKI_DomainID_t domain);

psa_status_t periph_common_ecc_sign_hash(const uint8_t * priv_key,
                                         uint32_t priv_key_size,
                                         const uint8_t *hash, size_t hash_length,
                                         uint8_t * signature,
                                         size_t * signature_length,
                                         CRYS_ECPKI_HASH_OpMode_t hash_mode,
                                         CRYS_ECPKI_DomainID_t domain);

psa_status_t periph_common_ecc_verify_hash(const uint8_t *pub_key, size_t pub_key_size,
                                           const uint8_t *hash, size_t hash_length,
                                           const uint8_t *signature, size_t signature_length,
                                           CRYS_ECPKI_HASH_OpMode_t hash_mode,
                                           CRYS_ECPKI_DomainID_t domain);
#endif /* PSA_PERIPH_ECC_COMMON_H */