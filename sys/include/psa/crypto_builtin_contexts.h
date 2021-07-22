#ifndef CRYPTO_BUILTIN_CONTEXTS_H
#define CRYPTO_BUILTIN_CONTEXTS_H

#include "psa/crypto_types.h"

#include "crypto/ciphers.h"

#include "hashes/md5.h"
#include "hashes/sha1.h"
#include "hashes/sha224.h"
#include "hashes/sha256.h"

typedef struct
{
    psa_algorithm_t alg;
    cipher_t cipher_ctx;
} psa_software_cipher_operation_t;

typedef union {
    unsigned dummy; /* Make the union non-empty even with no supported algorithms. */

#if IS_ACTIVE(CONFIG_BUILTIN_HASH_MD5)
    md5_ctx_t md5;
#endif
#if IS_ACTIVE(CONFIG_BUILTIN_HASH_SHA1)
    sha1_context sha1;
#endif
#if IS_ACTIVE(CONFIG_BUILTIN_HASH_SHA224)
    sha224_context_t sha224;
#endif
#if IS_ACTIVE(CONFIG_BUILTIN_HASH_SHA256)
    sha256_context_t sha256;
#endif
} psa_software_hash_operation_t;

#endif /* CRYPTO_BUILTIN_CONTEXTS_H */