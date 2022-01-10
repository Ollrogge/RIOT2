#include <stdio.h>
#include <stdint.h>

#include "psa/crypto.h"
#include "atca_params.h"

#if TEST_TIME
#include "periph/gpio.h"
gpio_t external_gpio = GPIO_PIN(1, 8);
gpio_t internal_gpio = GPIO_PIN(1, 7);
#endif

static const uint8_t HMAC_KEY[] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
};
static size_t HMAC_KEY_LEN = 32;

static const uint8_t HMAC_MSG[] = {
    0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
    0x61, 0x20, 0x74, 0x65, 0x73, 0x74, 0x73, 0x74,
    0x72, 0x69, 0x6e, 0x67, 0x20, 0x66, 0x6f, 0x72,
    0x20, 0x68, 0x6d, 0x61, 0x63, 0x32, 0x35, 0x36
};
static size_t HMAC_MSG_LEN = 32;

static void _test_init(void)
{
#if TEST_TIME
    gpio_init(external_gpio, GPIO_OUT);
    gpio_init(internal_gpio, GPIO_OUT);

    gpio_set(external_gpio);
    gpio_clear(internal_gpio);
#endif
    psa_crypto_init();
}

static void psa_hmac_sha256(void)
{
    psa_status_t status = PSA_ERROR_DOES_NOT_EXIST;

    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_key_id_t key_id = 0;
    psa_key_usage_t usage = PSA_KEY_USAGE_SIGN_MESSAGE;
    psa_key_lifetime_t lifetime = PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(PSA_KEY_LIFETIME_VOLATILE, PSA_ATCA_LOCATION_DEV0);

    size_t digest_size = PSA_MAC_LENGTH(PSA_KEY_TYPE_HMAC, HMAC_KEY_LEN, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    uint8_t digest[digest_size];
    size_t output_len = 0;

    psa_set_key_lifetime(&attr, lifetime);
    psa_set_key_algorithm(&attr, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_set_key_usage_flags(&attr, usage);
    psa_set_key_bits(&attr, PSA_BYTES_TO_BITS(HMAC_KEY_LEN));
    psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);

#if TEST_TIME
    gpio_clear(external_gpio);
    status = psa_import_key(&attr, HMAC_KEY, HMAC_KEY_LEN, &key_id);
    gpio_set(external_gpio);

    gpio_clear(external_gpio);
    status = psa_mac_compute(key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256), HMAC_MSG, HMAC_MSG_LEN, digest, digest_size, &output_len);
    gpio_set(external_gpio);
#else

    status = psa_import_key(&attr, HMAC_KEY, HMAC_KEY_LEN, &key_id);
    if (status != PSA_SUCCESS) {
        printf("MAC Key Import failed: %ld\n", status);
        return;
    }

    status = psa_mac_compute(key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256), HMAC_MSG, HMAC_MSG_LEN, digest, digest_size, &output_len);
    if (status != PSA_SUCCESS) {
        printf("MAC Compute failed: %ld\n", status);
        return;
    }
#endif
    puts("SE MAC Compute Done");
}

int main(void)
{
    _test_init();
    psa_crypto_init();
    psa_hmac_sha256();

    return 0;
}