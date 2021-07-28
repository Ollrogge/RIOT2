#ifndef CRYPTO_SOFTWARE_CONTEXTS_H
#define CRYPTO_SOFTWARE_CONTEXTS_H

#include "psa/crypto_types.h"

#include "crypto/ciphers.h"

#include "hashes/md5.h"
#include "hashes/sha1.h"
#include "hashes/sha224.h"
#include "hashes/sha256.h"

#if IS_ACTIVE(CONFIG_TINYCRYPT_HASHES)
#include "tinycrypt/sha256.h"
#endif
#if IS_ACTIVE(CONFIG_TINYCRYPT_CIPHER)
#include "tinycrypt/aes.h"
#endif

typedef struct
{
    psa_algorithm_t alg;
#if IS_ACTIVE(CONFIG_MODULE_PSA_SOFTWARE_CIPHER)
    cipher_t cipher_ctx;
#endif
#if IS_ACTIVE(CONFIG_TINYCRYPT_CIPHER)
    struct tc_aes_key_sched_struct tc_aes;
#endif
} psa_software_cipher_operation_t;

typedef union {
    unsigned dummy; /* Make the union non-empty even with no supported algorithms. */
#if IS_ACTIVE(CONFIG_RIOT_HASH_MD5)
    md5_ctx_t md5;
#endif
#if IS_ACTIVE(CONFIG_RIOT_HASH_SHA1)
    sha1_context sha1;
#endif
#if IS_ACTIVE(CONFIG_RIOT_HASH_SHA224)
    sha224_context_t sha224;
#endif
#if IS_ACTIVE(CONFIG_RIOT_HASH_SHA256)
    sha256_context_t sha256;
#endif
#if IS_ACTIVE(CONFIG_TINYCRYPT_HASHES)
    struct tc_sha256_state_struct tc_sha256;
#endif
} psa_software_hash_operation_t;

#endif /* CRYPTO_SOFTWARE_CONTEXTS_H */