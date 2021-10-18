#ifndef RIOT_CIPHERS_H
#define RIOT_CIPHERS_H

#include "crypto/ciphers.h"
#include "kernel_defines.h"

#if IS_ACTIVE(CONFIG_RIOT_CIPHER_AES_128_CBC)
typedef cipher_t psa_cipher_aes_128_ctx_t;
#endif
#if IS_ACTIVE(CONFIG_RIOT_CIPHER_AES_192_CBC)
typedef cipher_t psa_cipher_aes_192_ctx_t;
#endif
#if IS_ACTIVE(CONFIG_RIOT_CIPHER_AES_256_CBC)
typedef cipher_t psa_cipher_aes_256_ctx_t;
#endif

#endif
