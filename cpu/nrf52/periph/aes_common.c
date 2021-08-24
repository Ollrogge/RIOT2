#include "psa/crypto.h"
#include "vendor/nrf52840.h"
#include "cryptocell_incl/ssi_aes.h"
#include "cryptocell_incl/sns_silib.h"
#include "psa_periph_error.h"
#include "cryptocell_util.h"

#define CC310_MAX_AES_INPUT_BLOCK       (0xFFF0)

psa_status_t common_aes_setup(SaSiAesUserContext_t *ctx, SaSiAesEncryptMode_t direction, SaSiAesOperationMode_t mode, SaSiAesPaddingType_t padding)
{
    int ret = SaSi_AesInit(ctx, direction, mode, padding);
    if (ret != SASI_OK) {
        return SaSi_to_psa_error(ret);
    }

    return PSA_SUCCESS;
}

psa_status_t common_aes_update(SaSiAesUserContext_t *ctx, const uint8_t *input, size_t input_length, uint8_t *output)
{
    int ret = 0;
    size_t offset = 0;
    size_t size;

    do {
        if (input_length > CC310_MAX_AES_INPUT_BLOCK) {
            size = CC310_MAX_AES_INPUT_BLOCK;
            input_length -= CC310_MAX_AES_INPUT_BLOCK;
        }
        else {
            size = input_length;
            input_length = 0;
        }

        cryptocell_enable();
        ret = SaSi_AesBlock(ctx, (uint8_t*)(input + offset), size, output + offset);
        cryptocell_disable();
        if (ret != SASI_OK) {
        return SaSi_to_psa_error(ret);
        }

        offset += size;
    } while ((input_length > 0) && (ret == SASI_OK));

    return PSA_SUCCESS;
}
