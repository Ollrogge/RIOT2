#ifndef CRYPTO_INCLUDES_H
#define CRYPTO_INCLUDES_H

#include "kernel_defines.h"

#if IS_ACTIVE(CONFIG_MODULE_PSA_RIOT_CIPHER)
#include "crypto/psa/riot_ciphers.h"
#endif

#if IS_ACTIVE(CONFIG_PERIPH_CIPHER_AES)
#include "psa_periph_aes_ctx.h"
#endif

#if IS_ACTIVE(CONFIG_MODULE_PSA_RIOT_HASHES)
#include "hashes/psa/riot_hashes.h"
#endif

#if IS_ACTIVE(CONFIG_PERIPH_HASHES)
#include "psa_periph_hashes_ctx.h"
#endif

#if IS_ACTIVE(CONFIG_MODULE_PSA_TINYCRYPT)
#include "psa_tc_ctx.h"
#endif

#endif /* CRYPTO_INCLUDES_H */
