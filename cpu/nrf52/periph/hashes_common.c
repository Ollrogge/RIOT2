#include "psa/crypto.h"
#include "psa_periph_error.h"
#include "cryptocell_util.h"
#include "cryptocell_incl/crys_hash.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

#include "periph/gpio.h"
// extern gpio_t internal_gpio;

#define CC310_MAX_HASH_INPUT_BLOCK       (0xFFF0)

psa_status_t common_hash_setup(CRYS_HASHUserContext_t * ctx, CRYS_HASH_OperationMode_t mode)
{
    // gpio_set(internal_gpio);
    int ret = CRYS_HASH_Init(ctx, mode);
    // gpio_clear(internal_gpio);
    if (ret != CRYS_OK) {
        return CRYS_to_psa_error(ret);
    }
    return PSA_SUCCESS;
}

psa_status_t common_hash_update(CRYS_HASHUserContext_t * ctx,
                             const uint8_t * input,
                             size_t input_length)
{
    int ret = 0;
    size_t offset = 0;
    size_t size;
    do {
        if (input_length > CC310_MAX_HASH_INPUT_BLOCK) {
            size = CC310_MAX_HASH_INPUT_BLOCK;
            input_length -= CC310_MAX_HASH_INPUT_BLOCK;
        }
        else {
            size = input_length;
            input_length = 0;
        }

        cryptocell_enable();
        // gpio_set(internal_gpio);
        ret = CRYS_HASH_Update(ctx, (uint8_t*)(input + offset), size);
        // gpio_clear(internal_gpio);
        cryptocell_disable();

        offset += size;
    } while ((input_length > 0) && (ret == CRYS_OK));

    if (ret != CRYS_OK) {
        return CRYS_to_psa_error(ret);
    }
    return PSA_SUCCESS;
}

psa_status_t common_hash_finish(CRYS_HASHUserContext_t * ctx, uint8_t * hash, size_t hash_size, size_t * hash_length)
{
    cryptocell_enable();
    // gpio_set(internal_gpio);
    int ret = CRYS_HASH_Finish(ctx, (uint32_t *) hash);
    // gpio_clear(internal_gpio);
    cryptocell_disable();
    if (ret != CRYS_OK) {
        return CRYS_to_psa_error(ret);
    }

    *hash_length = hash_size;
    return PSA_SUCCESS;
}
