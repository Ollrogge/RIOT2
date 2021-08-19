#ifndef CRYPTO_INCLUDES_H
#define CRYPTO_INCLUDES_H

// #include "crypto/ciphers.h"

#if IS_ACTIVE(CONFIG_MODULE_PSA_RIOT_HASHES)
#include "hashes/psa/riot_hashes.h"
#endif

#if IS_ACTIVE(CONFIG_PERIPH_HASHES)
#include "psa_periph_hashes_ctx.h"
#endif

#if IS_ACTIVE(CONFIG_TINYCRYPT_HASHES_SHA256)
#include "tc_hash_ctx.h"
#endif

#endif /* CRYPTO_INCLUDES_H */
