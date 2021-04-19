#ifndef PSA_CRYPTO_STRUCT_H
#define PSA_CRYPTO_STRUCT_H

#include "psa/psa_crypto_types.h"
#include "kernel_defines.h"

#if IS_ACTIVE(CONFIG_HW_HASHES_ENABLED)
#include "psa_crypto_driver_wrapper.h"
#endif

#include "hashes/md5.h"
#include "hashes/sha1.h"
#include "hashes/sha224.h"
#include "hashes/sha256.h"

struct psa_hash_operation_s
{
    psa_algorithm_t alg;
    uint8_t suspended;
    #if IS_ACTIVE(CONFIG_HW_HASHES_ENABLED)
        psa_hash_hw_context_t hw_ctx;
    #endif /* CONFIG_HW_HASHES_ENABLED */
    union
    {
        unsigned dummy; /* Make the union non-empty even with no supported algorithms. */

        #if IS_ACTIVE(CONFIG_SW_HASH_MD5)
                md5_ctx_t md5;
        #endif
        #if IS_ACTIVE(CONFIG_SW_HASH_SHA1)
                sha1_context sha1;
        #endif
        #if IS_ACTIVE(CONFIG_SW_HASH_SHA224)
                sha224_context_t sha224;
        #endif
        #if IS_ACTIVE(CONFIG_SW_HASH_SHA256)
                sha256_context_t sha256;
        #endif
    } sw_ctx;
};

#if IS_ACTIVE(CONFIG_HW_HASHES_ENABLED)
#define PSA_HASH_OPERATION_INIT {0, 0, {0}, {0}}
#else
#define PSA_HASH_OPERATION_INIT {0, 0, {0}}
#endif /* CONFIG_HW_HASHES_ENABLED */

static inline struct psa_hash_operation_s psa_hash_operation_init( void )
{
    const struct psa_hash_operation_s v = PSA_HASH_OPERATION_INIT;
    return( v );
}

struct psa_key_attributes_s
{
    psa_algorithm_t alg;
    union
    {
        unsigned dummy; /* Make the union non-empty even with no supported algorithms. */
    } ctx;
};

#define PSA_KEY_ATTRIBUTES_INIT {0, {0}}//{PSA_CORE_KEY_ATTRIBUTES_INIT, NULL, 0}

static inline struct psa_key_attributes_s psa_key_attributes_init( void )
{
    const struct psa_key_attributes_s v = PSA_KEY_ATTRIBUTES_INIT;
    return( v );
}

#endif /* PSA_CRYPTO_STRUCT_H */
