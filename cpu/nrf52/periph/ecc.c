#include "psa/crypto.h"

#include "psa_periph_error.h"
#include "cryptocell_util.h"

#include "cryptocell_incl/sns_silib.h"
#include "cryptocell_incl/crys_ecpki_build.h"
#include "cryptocell_incl/crys_ecpki_ecdsa.h"
#include "cryptocell_incl/crys_ecpki_kg.h"
#include "cryptocell_incl/crys_ecpki_domain.h"

#define ENABLE_DEBUG    (1)
#include "debug.h"

#include "periph/gpio.h"
extern gpio_t internal_gpio;

#define MAP_PSA_HASH_TO_CRYS_HASH(hash) \
        ((hash == PSA_ALG_SHA_1) ? CRYS_ECPKI_AFTER_HASH_SHA1_mode : \
         (hash == PSA_ALG_SHA_224) ? CRYS_ECPKI_AFTER_HASH_SHA224_mode : \
         (hash == PSA_ALG_SHA_256) ? CRYS_ECPKI_AFTER_HASH_SHA256_mode : \
         (hash == PSA_ALG_SHA_384) ? CRYS_ECPKI_AFTER_HASH_SHA384_mode : \
         (hash == PSA_ALG_SHA_512) ? CRYS_ECPKI_AFTER_HASH_SHA512_mode : \
         0)

extern CRYS_RND_State_t*     rndState_ptr;

CRYS_ECPKI_Domain_t* pDomain;
SaSiRndGenerateVectWorkFunc_t rndGenerateVectFunc;

psa_status_t psa_generate_ecc_p192r1_key_pair(  const psa_key_attributes_t *attributes,
                                                psa_ecc_keypair_t *key_buffer, size_t key_buffer_size,
                                                size_t *key_buffer_length)
{
    int ret = 0;

    CRYS_ECPKI_UserPrivKey_t * priv_key = (CRYS_ECPKI_UserPrivKey_t *) &key_buffer->priv_key_data;
    CRYS_ECPKI_UserPublKey_t * pub_key = (CRYS_ECPKI_UserPublKey_t *) &key_buffer->pub_key_data;

    CRYS_ECPKI_KG_FipsContext_t FipsBuff;
    CRYS_ECPKI_KG_TempData_t TempECCKGBuff;
    rndGenerateVectFunc = CRYS_RND_GenerateVector;
    pDomain = (CRYS_ECPKI_Domain_t*)CRYS_ECPKI_GetEcDomain(CRYS_ECPKI_DomainID_secp192r1);

    cryptocell_enable();
    gpio_set(internal_gpio);
    ret = CRYS_ECPKI_GenKeyPair(rndState_ptr, rndGenerateVectFunc, pDomain, priv_key, pub_key, &TempECCKGBuff, &FipsBuff);
    gpio_clear(internal_gpio);
    cryptocell_disable();

    if (ret != CRYS_OK){
        DEBUG("CRYS_ECPKI_GenKeyPair failed with 0x%x \n", ret);
        return CRYS_to_psa_error(ret);
    }

    *key_buffer_length = key_buffer_size;
    (void) attributes;
    return PSA_SUCCESS;
}

psa_status_t psa_ecc_p192r1_sign_hash(  const psa_key_attributes_t *attributes,
                                        psa_algorithm_t alg,
                                        const uint8_t *key_buffer, size_t key_buffer_size,
                                        const uint8_t *hash, size_t hash_length,
                                        uint8_t * signature, size_t signature_size,
                                        size_t * signature_length)
{
    int ret = 0;

    CRYS_ECDSA_SignUserContext_t SignUserContext;

    rndGenerateVectFunc = CRYS_RND_GenerateVector;

    CRYS_ECPKI_HASH_OpMode_t hash_mode = MAP_PSA_HASH_TO_CRYS_HASH(PSA_ALG_GET_HASH(alg));

    cryptocell_enable();
    gpio_set(internal_gpio);
    ret = CRYS_ECDSA_Sign (rndState_ptr, rndGenerateVectFunc,
    &SignUserContext, (CRYS_ECPKI_UserPrivKey_t *) key_buffer, hash_mode, (uint8_t *) hash, hash_length, signature, (uint32_t *) signature_length);
    gpio_clear(internal_gpio);
    cryptocell_disable();

    if (ret != CRYS_OK){
        DEBUG("CRYS_ECDSA_Sign failed with 0x%x \n", ret);
        return CRYS_to_psa_error(ret);
    }

    (void) attributes;
    (void) key_buffer_size;
    (void) signature_size;
    return PSA_SUCCESS;
}

psa_status_t psa_ecc_p192r1_verify_hash(const psa_key_attributes_t *attributes,
                                        psa_algorithm_t alg,
                                        const uint8_t *key_buffer, size_t key_buffer_size,
                                        const uint8_t *hash, size_t hash_length,
                                        const uint8_t *signature, size_t signature_length)
{
    int ret = 0;

    CRYS_ECDSA_VerifyUserContext_t VerifyUserContext;

    CRYS_ECPKI_HASH_OpMode_t hash_mode = MAP_PSA_HASH_TO_CRYS_HASH(PSA_ALG_GET_HASH(alg));

    cryptocell_enable();
    gpio_set(internal_gpio);
    ret =  CRYS_ECDSA_Verify (&VerifyUserContext, (CRYS_ECPKI_UserPublKey_t *) key_buffer, hash_mode, (uint8_t *) signature, signature_length, (uint8_t *) hash, hash_length);
    gpio_clear(internal_gpio);
    cryptocell_disable();

    if (ret != CRYS_OK){
        DEBUG("CRYS_ECDSA_Verify failed with 0x%x \n", ret);
        return CRYS_to_psa_error(ret);
    }

    (void) attributes;
    (void) key_buffer_size;
    return PSA_SUCCESS;
}