#include "psa/crypto.h"
#include "hashes/psa/riot_hashes.h"

#include "periph/gpio.h"
extern gpio_t internal_gpio;

psa_status_t psa_hashes_sha256_setup(psa_hashes_sha256_ctx_t * ctx)
{
    gpio_set(internal_gpio);
    sha256_init((sha256_context_t *) ctx);
    gpio_clear(internal_gpio);
    return PSA_SUCCESS;
}

psa_status_t psa_hashes_sha256_update(psa_hashes_sha256_ctx_t * ctx,
                             const uint8_t * input,
                             size_t input_length)
{
    gpio_set(internal_gpio);
    sha256_update((sha256_context_t *) ctx, input, input_length);
    gpio_clear(internal_gpio);
    return PSA_SUCCESS;
}

psa_status_t psa_hashes_sha256_finish(psa_hashes_sha256_ctx_t * ctx,
                             uint8_t * hash,
                             size_t hash_size,
                             size_t * hash_length)
{
    gpio_set(internal_gpio);
    sha256_final((sha256_context_t *) ctx, hash);
    gpio_clear(internal_gpio);

    (void) hash_size;
    (void) hash_length;
    return PSA_SUCCESS;
}
