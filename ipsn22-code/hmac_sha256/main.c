#include <stdio.h>
#include <stdint.h>

#include "periph/gpio.h"
#include "psa/crypto.h"
#include "atca_params.h"

#ifdef TEST_STACK
#include "ps.h"
#endif

#include "xtimer.h"

#define AES_128_KEY_SIZE    (16)
#define AES_256_KEY_SIZE    (32)

gpio_t external_gpio = GPIO_PIN(1, 8);
gpio_t internal_gpio = GPIO_PIN(1, 7);

static const uint8_t KEY_128[] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

// static const uint8_t KEY_256[] = {
//     0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
//     0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
//     0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
//     0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
// };

static uint8_t PLAINTEXT[] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
};
static uint8_t PLAINTEXT_LEN = 32;

static void _test_init(void)
{
    gpio_init(external_gpio, GPIO_OUT);
    gpio_init(internal_gpio, GPIO_OUT);

    gpio_set(external_gpio);
    gpio_clear(internal_gpio);
}

static void hmac_sha256(void)
{
    psa_status_t status = PSA_ERROR_DOES_NOT_EXIST;

    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_key_id_t key_id = 0;
    psa_key_usage_t usage = PSA_KEY_USAGE_SIGN_MESSAGE;
    psa_key_lifetime_t lifetime = PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(PSA_KEY_LIFETIME_VOLATILE, PSA_ATCA_LOCATION_DEV0);

    size_t digest_size = PSA_MAC_LENGTH(PSA_KEY_TYPE_AES, AES_128_KEY_SIZE, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    uint8_t digest[digest_size];
    size_t output_len = 0;

    psa_set_key_lifetime(&attr, lifetime);
    psa_set_key_algorithm(&attr, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_set_key_usage_flags(&attr, usage);
    psa_set_key_bits(&attr, PSA_BYTES_TO_BITS(AES_128_KEY_SIZE));
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);

    gpio_clear(external_gpio);
    status = psa_import_key(&attr, KEY_128, AES_128_KEY_SIZE, &key_id);
    gpio_set(external_gpio);
    if (status != PSA_SUCCESS) {
        printf("MAC Key Import failed: %ld\n", status);
        return;
    }

    gpio_clear(external_gpio);
    status = psa_mac_compute(key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256), PLAINTEXT, PLAINTEXT_LEN, digest, digest_size, &output_len);
    gpio_set(external_gpio);
    if (status != PSA_SUCCESS) {
        printf("MAC Compute failed: %ld\n", status);
        return;
    }
    puts("MAC Compute Success");
}

int main(void)
{
    _test_init();
    psa_crypto_init();
    hmac_sha256();

#ifdef TEST_STACK
    ps();
#endif
    return 0;
}