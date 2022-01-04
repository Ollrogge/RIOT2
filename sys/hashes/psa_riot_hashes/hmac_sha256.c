#include "psa/crypto.h"
#include "hashes/psa/riot_hashes.h"

#include "periph/gpio.h"
// extern gpio_t internal_gpio;

psa_status_t psa_mac_hmac_sha256(   const uint8_t * key_buffer,
                                    size_t key_buffer_size,
                                    const uint8_t * input,
                                    size_t input_length,
                                    uint8_t * mac,
                                    size_t mac_size,
                                    size_t * mac_length)
{
    // gpio_set(internal_gpio);
    sha256_init((sha256_context_t *) ctx);
    // gpio_clear(internal_gpio);
    return PSA_SUCCESS;
}

