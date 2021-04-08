#ifndef PSA_CRYPTO_STRUCT_H
#define PSA_CRYPTO_STRUCT_H

#include "psa/psa_crypto_types.h"

#if defined(CONFIG_MODULE_PERIPH_HW_HASHES)
#include "hash_hwctx.h"
#endif

#include "hashes/md5.h"
#include "hashes/sha1.h"
#include "hashes/sha224.h"
#include "hashes/sha256.h"

#include "kernel_defines.h"

struct psa_hash_operation_s
{
    psa_algorithm_t alg;
    uint8_t suspended;
    union
    {
        unsigned dummy; /* Make the union non-empty even with no supported algorithms. */

        #if IS_ACTIVE(CONFIG_HASHES_MD5)
                #if defined(CONFIG_MOD_PERIPH_HASH_MD5)
                        md5_hwctx_t md5;
                #else
                        md5_ctx_t md5;
                #endif
        #endif
        #if IS_ACTIVE(CONFIG_HASHES_SHA1)
                #if defined(CONFIG_MOD_PERIPH_HASH_SHA1) 
                        sha1_hwctx_t sha1;
                #else
                        sha1_context sha1;
                #endif
        #endif
        #if IS_ACTIVE(CONFIG_HASHES_SHA224)
                #if defined(CONFIG_MOD_PERIPH_HASH_SHA224) 
                        sha224_hwctx_t sha224;
                #else
                        sha224_context_t sha224;
                #endif
        #endif
        #if IS_ACTIVE(CONFIG_HASHES_SHA256)
                #if defined(CONFIG_MOD_PERIPH_HASH_SHA256)
                        sha256_hwctx_t sha256;
                #else
                        sha256_context_t sha256;
                #endif
        #endif
    } ctx;
};

#define PSA_HASH_OPERATION_INIT {0, 0, {0}}
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
