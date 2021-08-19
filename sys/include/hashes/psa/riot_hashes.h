#ifndef RIOT_HASHES_H
#define RIOT_HASHES_H

#include "kernel_defines.h"

#if IS_ACTIVE(CONFIG_RIOT_HASHES_MD5)
#include "hashes/md5.h"

typedef md5_ctx_t psa_hashes_md5_ctx_t;
#endif

#if IS_ACTIVE(CONFIG_RIOT_HASHES_SHA1)
#include "hashes/sha1.h"

typedef sha1_context psa_hashes_sha1_ctx_t;
#endif

#if IS_ACTIVE(CONFIG_RIOT_HASHES_SHA224)
#include "hashes/sha224.h"

typedef sha224_context_t psa_hashes_sha224_ctx_t;
#endif

#if IS_ACTIVE(CONFIG_RIOT_HASHES_SHA256)
#include "hashes/sha256.h"

typedef sha256_context_t psa_hashes_sha256_ctx_t;
#endif

#endif /* RIOT_HASHES_H */
