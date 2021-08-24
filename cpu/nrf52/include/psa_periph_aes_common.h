#ifndef PSA_PERIPH_AES_COMMON_H
#define PSA_PERIPH_AES_COMMON_H

#include "psa/crypto.h"

psa_status_t common_aes_setup(SaSiAesUserContext_t *ctx, SaSiAesEncryptMode_t direction, SaSiAesOperationMode_t mode, SaSiAesPaddingType_t padding);
psa_status_t common_aes_update(SaSiAesUserContext_t *ctx, const uint8_t *input, size_t input_length, uint8_t *output);

#endif /* PSA_PERIPH_AES_COMMON_H */
