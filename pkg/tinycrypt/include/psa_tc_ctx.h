#ifndef TC_HASH_CTX_H
#define TC_HASH_CTX_H

#include "kernel_defines.h"

#if IS_ACTIVE(CONFIG_TINYCRYPT_HASHES_SHA256)
#include "tinycrypt/sha256.h"

typedef struct tc_sha256_state_struct psa_hashes_sha256_ctx_t;
#endif

#if IS_ACTIVE(CONFIG_PSA_TINYCRYPT_CIPHER_AES_128)
#include "tinycrypt/aes.h"

typedef struct tc_aes_key_sched_struct psa_cipher_aes_ctx_t;
#endif

#endif /* TC_HASH_CTX_H */
