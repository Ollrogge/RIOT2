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
                                                uint8_t * priv_key_buffer, uint8_t * pub_key_buffer,
                                                size_t *priv_key_buffer_length, size_t *pub_key_buffer_length)
{
    int ret = 0;

    CRYS_ECPKI_UserPrivKey_t priv_key;
    CRYS_ECPKI_UserPublKey_t pub_key;

    CRYS_ECPKI_KG_FipsContext_t FipsBuff;
    CRYS_ECPKI_KG_TempData_t TempECCKGBuff;
    rndGenerateVectFunc = CRYS_RND_GenerateVector;
    pDomain = (CRYS_ECPKI_Domain_t*)CRYS_ECPKI_GetEcDomain(CRYS_ECPKI_DomainID_secp192r1);

    uint32_t priv_key_size = PSA_BITS_TO_BYTES(attributes->bits);
    uint32_t pub_key_size = PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(attributes->type, attributes->bits);

    cryptocell_enable();
    gpio_set(internal_gpio);
    ret = CRYS_ECPKI_GenKeyPair(rndState_ptr, rndGenerateVectFunc, pDomain, &priv_key, &pub_key, &TempECCKGBuff, &FipsBuff);
    gpio_clear(internal_gpio);
    cryptocell_disable();
    if (ret != CRYS_OK){
        DEBUG("CRYS_ECPKI_GenKeyPair failed with 0x%x \n", ret);
        return CRYS_to_psa_error(ret);
    }

    ret = CRYS_ECPKI_ExportPrivKey(&priv_key, priv_key_buffer, &priv_key_size);
    if (ret != CRYS_OK){
        DEBUG("CRYS_ECPKI_ExportPrivKey failed with 0x%x \n", ret);
        return CRYS_to_psa_error(ret);
    }

    ret = CRYS_ECPKI_ExportPublKey(&pub_key, CRYS_EC_PointUncompressed, pub_key_buffer, &pub_key_size);
    if (ret != CRYS_OK){
        DEBUG("CRYS_ECPKI_ExportPubKey failed with 0x%x \n", ret);
        return CRYS_to_psa_error(ret);
    }

    *priv_key_buffer_length = priv_key_size;
    *pub_key_buffer_length = pub_key_size;

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
    CRYS_ECPKI_UserPrivKey_t priv_key;
    CRYS_ECPKI_HASH_OpMode_t hash_mode = MAP_PSA_HASH_TO_CRYS_HASH(PSA_ALG_GET_HASH(alg));
    rndGenerateVectFunc = CRYS_RND_GenerateVector;
    pDomain = (CRYS_ECPKI_Domain_t*)CRYS_ECPKI_GetEcDomain(CRYS_ECPKI_DomainID_secp192r1);

    ret = CRYS_ECPKI_BuildPrivKey(pDomain, key_buffer, PSA_BITS_TO_BYTES(attributes->bits), &priv_key);
    if (ret != CRYS_OK){
        DEBUG("CRYS_ECPKI_BuildPrivKey failed with 0x%x \n", ret);
        return CRYS_to_psa_error(ret);
    }

    cryptocell_enable();
    gpio_set(internal_gpio);
    ret = CRYS_ECDSA_Sign (rndState_ptr, rndGenerateVectFunc,
    &SignUserContext, &priv_key, hash_mode, (uint8_t *) hash, hash_length, signature, (uint32_t *) signature_length);
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
    CRYS_ECPKI_UserPublKey_t pub_key;
    CRYS_ECPKI_HASH_OpMode_t hash_mode = MAP_PSA_HASH_TO_CRYS_HASH(PSA_ALG_GET_HASH(alg));
    pDomain = (CRYS_ECPKI_Domain_t*)CRYS_ECPKI_GetEcDomain(CRYS_ECPKI_DomainID_secp192r1);

    printf("PubKeySize: %d\n", key_buffer_size);
    /* For more security, use CRYS_ECPKI_BuildPublKeyPartlyCheck or CRYS_ECPKI_BuildPublKeyFullCheck -> Those take longer and use more memory space */
    ret = CRYS_ECPKI_BuildPublKey(pDomain, (uint8_t *) key_buffer, key_buffer_size, &pub_key);
    if (ret != CRYS_OK){
        DEBUG("CRYS_ECPKI_BuildPublKey failed with 0x%x \n", ret);
        return CRYS_to_psa_error(ret);
    }

    cryptocell_enable();
    gpio_set(internal_gpio);
    ret =  CRYS_ECDSA_Verify (&VerifyUserContext, &pub_key, hash_mode, (uint8_t *) signature, signature_length, (uint8_t *) hash, hash_length);
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