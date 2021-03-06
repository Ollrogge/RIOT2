#include <stdio.h>
#include "psa_crypto_driver_wrapper.h"
#include "psa/psa_crypto_struct.h"

#include "cryptocell_util.h"
#include "cryptocell_incl/crys_hash.h"
#include "cryptocell_incl/crys_hash_error.h"

#define CC310_MAX_HASH_INPUT_BLOCK       (0xFFF0)

static psa_status_t cc310_to_psa_error(CRYSError_t error)
{
    switch(error) {
        case CRYS_HASH_ILLEGAL_OPERATION_MODE_ERROR:
        case CRYS_HASH_IS_NOT_SUPPORTED:
            return PSA_ERROR_NOT_SUPPORTED;
        case CRYS_HASH_USER_CONTEXT_CORRUPTED_ERROR:
            return PSA_ERROR_CORRUPTION_DETECTED;
        case CRYS_HASH_DATA_IN_POINTER_INVALID_ERROR:
        case CRYS_HASH_DATA_SIZE_ILLEGAL:
            return PSA_ERROR_DATA_INVALID;
        case CRYS_HASH_INVALID_RESULT_BUFFER_POINTER_ERROR:
        case CRYS_HASH_ILLEGAL_PARAMS_ERROR:
        case CRYS_HASH_INVALID_USER_CONTEXT_POINTER_ERROR:
        case CRYS_HASH_LAST_BLOCK_ALREADY_PROCESSED_ERROR: 
        case CRYS_HASH_CTX_SIZES_ERROR:
            return PSA_ERROR_INVALID_ARGUMENT;
        default:
            return PSA_ERROR_GENERIC_ERROR;       
    }
}

psa_status_t psa_driver_wrapper_hash_setup(psa_hash_operation_t * operation,
                                           psa_algorithm_t alg)
{
    puts("Setup PSA HW accelerated implementation\n");
    int ret = 0;
    
    switch(alg) {
#if defined(CONFIG_MOD_PERIPH_HASH_MD5)
        case PSA_ALG_MD5:
            ret = CRYS_HASH_Init(&operation->ctx.md5, CRYS_HASH_MD5_mode);
            break;
#endif
#if defined(CONFIG_MOD_PERIPH_HASH_SHA1)
        case PSA_ALG_SHA_1:
            ret = CRYS_HASH_Init(&operation->ctx.sha1, CRYS_HASH_SHA1_mode);
            break;
#endif
#if defined(CONFIG_MOD_PERIPH_HASH_SHA224)
        case PSA_ALG_SHA_224:
            ret = CRYS_HASH_Init(&operation->ctx.sha224, CRYS_HASH_SHA224_mode);
            break;
#endif
#if defined(CONFIG_MOD_PERIPH_HASH_SHA256)
        case PSA_ALG_SHA_256:
            ret = CRYS_HASH_Init(&operation->ctx.sha256, CRYS_HASH_SHA256_mode);
            break;
#endif
        default:
            (void) operation;
            return PSA_ERROR_NOT_SUPPORTED;
    }

    if (ret != CRYS_OK) {
        return cc310_to_psa_error(ret);
    }
    return PSA_SUCCESS;
}

psa_status_t psa_driver_wrapper_hash_update(psa_hash_operation_t * operation,
                             const uint8_t * input,
                             size_t input_length)
{
    int ret = 0;
    size_t offset = 0;
    size_t size;

    do {
        if (input_length > CC310_MAX_HASH_INPUT_BLOCK) {
            size = CC310_MAX_HASH_INPUT_BLOCK;
            input_length -= CC310_MAX_HASH_INPUT_BLOCK;
        }
        else {
            size = input_length;
            input_length = 0;
        }

        switch(operation->alg) {
        #if defined(CONFIG_MOD_PERIPH_HASH_MD5)
                case PSA_ALG_MD5:
                    cryptocell_enable();
                    ret = CRYS_HASH_Update(&operation->ctx.md5, (uint8_t*)(input + offset), size);
                    cryptocell_disable();
                    break;
        #endif
        #if defined(CONFIG_MOD_PERIPH_HASH_SHA1)
                case PSA_ALG_SHA_1:
                    cryptocell_enable();
                    ret = CRYS_HASH_Update(&operation->ctx.sha1, (uint8_t*)(input + offset), size);
                    cryptocell_disable();
                    break;
        #endif
        #if defined(CONFIG_MOD_PERIPH_HASH_SHA224)
                case PSA_ALG_SHA_224:
                    cryptocell_enable();
                    ret = CRYS_HASH_Update(&operation->ctx.sha224, (uint8_t*)(input + offset), size);
                    cryptocell_disable();
                    break;
        #endif
        #if defined(CONFIG_MOD_PERIPH_HASH_SHA256)
                case PSA_ALG_SHA_256:
                    cryptocell_enable();
                    ret = CRYS_HASH_Update(&operation->ctx.sha256, (uint8_t*)(input + offset), size);
                    cryptocell_disable();
                    break;
        #endif
                default:
                    (void) operation;
                    (void) input;
                    return PSA_ERROR_NOT_SUPPORTED;
    }
        offset += size;
    } while ((input_length > 0) && (ret == CRYS_OK));

    if (ret != CRYS_OK) {
        return cc310_to_psa_error(ret);
    }
    return PSA_SUCCESS;
}

psa_status_t psa_driver_wrapper_hash_finish(psa_hash_operation_t * operation,
                             uint8_t * hash)
{
    int ret = 0;
    
    switch(operation->alg) {
        #if defined(CONFIG_MOD_PERIPH_HASH_MD5)
                case PSA_ALG_MD5:
                    cryptocell_enable();
                    ret = CRYS_HASH_Finish(&operation->ctx.md5, (uint32_t*)hash);
                    cryptocell_disable();
                    break;
        #endif
        #if defined(CONFIG_MOD_PERIPH_HASH_SHA1)
                case PSA_ALG_SHA_1:
                    cryptocell_enable();
                    ret = CRYS_HASH_Finish(&operation->ctx.sha1, (uint32_t*)hash);
                    cryptocell_disable();
                    break;
        #endif
        #if defined(CONFIG_MOD_PERIPH_HASH_SHA224)
                case PSA_ALG_SHA_224:
                    cryptocell_enable();
                    ret = CRYS_HASH_Finish(&operation->ctx.sha224, (uint32_t*)hash);
                    cryptocell_disable();
                    break;
        #endif
        #if defined(CONFIG_MOD_PERIPH_HASH_SHA256)
                case PSA_ALG_SHA_256:
                    cryptocell_enable();
                    ret = CRYS_HASH_Finish(&operation->ctx.sha256, (uint32_t*)hash);
                    cryptocell_disable();
                    break;
        #endif
                default:
                    (void) operation;
                    (void) hash;
                    return PSA_ERROR_NOT_SUPPORTED;
    }
    if (ret != CRYS_OK) {
        return cc310_to_psa_error(ret);
    }
    return PSA_SUCCESS;
}