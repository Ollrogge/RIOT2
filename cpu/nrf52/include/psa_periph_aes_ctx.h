#ifndef PSA_PERIPH_AES_CTX_H
#define PSA_PERIPH_AES_CTX_H

#include "cryptocell_incl/ssi_aes.h"
#include "kernel_defines.h"

#if IS_ACTIVE(CONFIG_PERIPH_CIPHER_AES_128_CBC)
typedef SaSiAesUserContext_t psa_cipher_aes_128_ctx_t;
#endif

#endif /* PSA_PERIPH_AES_CTX_H */
