#include "psa_periph_error.h"
#include "psa_periph_ecc_common.h"
#include "cryptocell_util.h"

#define ENABLE_DEBUG    (1)
#include "debug.h"

#include "periph/gpio.h"
extern gpio_t internal_gpio;

extern CRYS_RND_State_t*     rndState_ptr;

CRYS_ECPKI_Domain_t* pDomain;
SaSiRndGenerateVectWorkFunc_t rndGenerateVectFunc;

psa_status_t periph_common_ecc_generate_key_pair(uint8_t * priv_key_buffer,
                                                 uint8_t * pub_key_buffer,
                                                 uint32_t * priv_key_buffer_length,
                                                 uint32_t * pub_key_buffer_length,
                                                 CRYS_ECPKI_DomainID_t domain)
{
    CRYS_ECPKI_UserPrivKey_t priv_key;
    CRYS_ECPKI_UserPublKey_t pub_key;
    CRYS_ECPKI_KG_FipsContext_t FipsBuff;
    CRYS_ECPKI_KG_TempData_t TempECCKGBuff;
    int ret;

    rndGenerateVectFunc = CRYS_RND_GenerateVector;
    pDomain = (CRYS_ECPKI_Domain_t*)CRYS_ECPKI_GetEcDomain(domain);

    cryptocell_enable();
    gpio_set(internal_gpio);
    ret = CRYS_ECPKI_GenKeyPair(rndState_ptr, rndGenerateVectFunc, pDomain, &priv_key, &pub_key, &TempECCKGBuff, &FipsBuff);
    gpio_clear(internal_gpio);
    cryptocell_disable();
    if (ret != CRYS_OK){
        DEBUG("CRYS_ECPKI_GenKeyPair failed with 0x%x \n", ret);
        return CRYS_to_psa_error(ret);
    }

    gpio_set(internal_gpio);
    ret = CRYS_ECPKI_ExportPrivKey(&priv_key, priv_key_buffer, priv_key_buffer_length);
    if (ret != CRYS_OK){
        DEBUG("CRYS_ECPKI_ExportPrivKey failed with 0x%x \n", ret);
        return CRYS_to_psa_error(ret);
    }

    ret = CRYS_ECPKI_ExportPublKey(&pub_key, CRYS_EC_PointUncompressed, pub_key_buffer, pub_key_buffer_length);
    gpio_clear(internal_gpio);
    if (ret != CRYS_OK){
        DEBUG("CRYS_ECPKI_ExportPubKey failed with 0x%x \n", ret);
        return CRYS_to_psa_error(ret);
    }

    return PSA_SUCCESS;
}

psa_status_t periph_common_ecc_sign_hash(const uint8_t * priv_key,
                                         uint32_t priv_key_size,
                                         const uint8_t *hash, size_t hash_length,
                                         uint8_t * signature,
                                         size_t * signature_length,
                                         CRYS_ECPKI_HASH_OpMode_t hash_mode,
                                         CRYS_ECPKI_DomainID_t domain)
{
    CRYS_ECDSA_SignUserContext_t SignUserContext;
    CRYS_ECPKI_UserPrivKey_t user_priv_key;
    int ret;

    rndGenerateVectFunc = CRYS_RND_GenerateVector;
    pDomain = (CRYS_ECPKI_Domain_t*)CRYS_ECPKI_GetEcDomain(domain);

    gpio_set(internal_gpio);
    ret = CRYS_ECPKI_BuildPrivKey(pDomain, priv_key, priv_key_size, &user_priv_key);
    gpio_clear(internal_gpio);
    if (ret != CRYS_OK){
        DEBUG("CRYS_ECPKI_BuildPrivKey failed with 0x%x \n", ret);
        return CRYS_to_psa_error(ret);
    }

    cryptocell_enable();
    gpio_set(internal_gpio);
    ret = CRYS_ECDSA_Sign (rndState_ptr, rndGenerateVectFunc,
    &SignUserContext, &user_priv_key, hash_mode, (uint8_t *) hash, hash_length, signature, (uint32_t *) signature_length);
    gpio_clear(internal_gpio);
    cryptocell_disable();
    if (ret != CRYS_OK){
        DEBUG("CRYS_ECDSA_Sign failed with 0x%x \n", ret);
        return CRYS_to_psa_error(ret);
    }

    return PSA_SUCCESS;
}

psa_status_t periph_common_ecc_verify_hash(const uint8_t *pub_key, size_t pub_key_size,
                                           const uint8_t *hash, size_t hash_length,
                                           const uint8_t *signature, size_t signature_length,
                                           CRYS_ECPKI_HASH_OpMode_t hash_mode,
                                           CRYS_ECPKI_DomainID_t domain)
{
    CRYS_ECDSA_VerifyUserContext_t VerifyUserContext;
    CRYS_ECPKI_UserPublKey_t user_pub_key;
    int ret = 0;

    pDomain = (CRYS_ECPKI_Domain_t*)CRYS_ECPKI_GetEcDomain(domain);

    /* For more security, use CRYS_ECPKI_BuildPublKeyPartlyCheck or CRYS_ECPKI_BuildPublKeyFullCheck -> Those take longer and use more memory space */
    gpio_set(internal_gpio);
    ret = CRYS_ECPKI_BuildPublKey(pDomain, (uint8_t *) pub_key, pub_key_size, &user_pub_key);
    gpio_clear(internal_gpio);
    if (ret != CRYS_OK){
        DEBUG("CRYS_ECPKI_BuildPublKey failed with 0x%x \n", ret);
        return CRYS_to_psa_error(ret);
    }

    cryptocell_enable();
    gpio_set(internal_gpio);
    ret =  CRYS_ECDSA_Verify (&VerifyUserContext, &user_pub_key, hash_mode, (uint8_t *) signature, signature_length, (uint8_t *) hash, hash_length);
    gpio_clear(internal_gpio);
    cryptocell_disable();

    if (ret != CRYS_OK){
        DEBUG("CRYS_ECDSA_Verify failed with 0x%x \n", ret);
        return CRYS_to_psa_error(ret);
    }
    return PSA_SUCCESS;
}