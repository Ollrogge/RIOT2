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

#if IS_ACTIVE(CONFIG_CIFRA_HASHES)
#include "sha1.h"
#include "sha2.h"
#endif
#if IS_ACTIVE(CONFIG_CIFRA_CIPHER)
#include "aes.h"
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
#if IS_ACTIVE(CONFIG_CIFRA_CIPHER)
    cf_aes_context cf_aes;
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
#if IS_ACTIVE(CONFIG_CIFRA_HASHES_SHA1)
    cf_sha1_context cf_sha1;
#endif
#if IS_ACTIVE(CONFIG_CIFRA_HASHES_SHA224) || IS_ACTIVE(CONFIG_CIFRA_HASHES_SHA256)
    cf_sha256_context cf_sha256;
#endif
#if IS_ACTIVE(CONFIG_CIFRA_HASHES_SHA384) || IS_ACTIVE(CONFIG_CIFRA_HASHES_SHA512)
    cf_sha512_context cf_sha512;
#endif
} psa_software_hash_operation_t;

#endif /* CRYPTO_SOFTWARE_CONTEXTS_H */