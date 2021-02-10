#ifndef PSA_CRYPTO_STRUCT_H
#define PSA_CRYPTO_STRUCT_H

#include "psa/psa_crypto_types.h"

#if defined(HAVE_OWN_HASH_CTX)
#include "hash_hwctx.h"
#endif
#include "hashes/md5.h"
#include "hashes/sha1.h"
#include "hashes/sha224.h"
#include "hashes/sha256.h"
// #endif

struct psa_hash_operation_s
{
    psa_algorithm_t alg;
    uint8_t suspended;
    union
    {
        unsigned dummy; /* Make the union non-empty even with no supported algorithms. */
#if defined(HAVE_OWN_HASH_CTX)
        hash_hwctx_t hwctx;
#else
        #if defined(MODULE_HASHES_SW_MD5)
                md5_ctx_t md5;
        #endif
        #if defined(MODULE_HASHES_SW_SHA1)
                sha1_context sha1;
        #endif
        #if defined(MODULE_HASHES_SW_SHA224)
                sha224_context_t sha224;
        #endif
        #if defined(MODULE_HASHES_SW_SHA256)
                sha256_context_t sha256;
        #endif
#endif /* CONFIG_HAVE_OWN_HASH_CTX */
    } ctx;
};

#define PSA_HASH_OPERATION_INIT {0, 0, {0}}
static inline struct psa_hash_operation_s psa_hash_operation_init( void )
{
    const struct psa_hash_operation_s v = PSA_HASH_OPERATION_INIT;
    return( v );
}

#endif /* PSA_CRYPTO_STRUCT_H */
