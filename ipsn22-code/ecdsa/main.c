#include <stdio.h>
#include <stdint.h>

#include "psa/crypto.h"

#ifdef TEST_STACK
#include "ps.h"
#endif

#include "xtimer.h"
#include "periph/gpio.h"
gpio_t external_gpio = GPIO_PIN(1, 8);
gpio_t internal_gpio = GPIO_PIN(1, 7);

#define ECDSA_MESSAGE_SIZE  (127)

static void _test_init(void)
{
    gpio_init(external_gpio, GPIO_OUT);
    gpio_init(internal_gpio, GPIO_OUT);

    gpio_set(external_gpio);
    gpio_clear(internal_gpio);
    xtimer_sleep(1);
}

static void ecdsa_periph(void)
{
    psa_status_t status = PSA_ERROR_DOES_NOT_EXIST;

    psa_key_id_t privkey_id;
    psa_key_attributes_t privkey_attr = psa_key_attributes_init();

    psa_key_usage_t usage = PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH;
    psa_key_type_t type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
    psa_algorithm_t alg =  PSA_ALG_ECDSA(PSA_ALG_SHA_256);
    psa_key_bits_t bits = PSA_VENDOR_ECC_MAX_CURVE_BITS;

    uint8_t signature[PSA_SIGN_OUTPUT_SIZE(type, bits, alg)];
    size_t sig_length;
    uint8_t msg[ECDSA_MESSAGE_SIZE] = { 0x0b };
    uint8_t hash[PSA_HASH_LENGTH(PSA_ALG_SHA_256)];
    size_t hash_length;

    psa_set_key_algorithm(&privkey_attr, alg);
    psa_set_key_usage_flags(&privkey_attr, usage);
    psa_set_key_type(&privkey_attr, type);
    psa_set_key_bits(&privkey_attr, bits);

    gpio_clear(external_gpio);
    status = psa_generate_key(&privkey_attr, &privkey_id);
    gpio_set(external_gpio);
    if (status != PSA_SUCCESS) {
        printf("Local Generate Key failed: %ld\n", status);
        return;
    }

    gpio_clear(external_gpio);
    status = psa_hash_compute(PSA_ALG_SHA_256, msg, sizeof(msg), hash, sizeof(hash), &hash_length);
    gpio_set(external_gpio);
    if (status != PSA_SUCCESS) {
        printf("Hash Generation failed: %ld\n", status);
        return;
    }

    gpio_clear(external_gpio);
    status = psa_sign_hash(privkey_id, alg, hash, sizeof(hash), signature, sizeof(signature), &sig_length);
    gpio_set(external_gpio);
    if (status != PSA_SUCCESS) {
        printf("Periph Sign hash failed: %ld\n", status);
        return;
    }

    gpio_clear(external_gpio);
    status = psa_verify_hash(privkey_id, alg, hash, sizeof(hash), signature, sig_length);
    gpio_set(external_gpio);
    if (status != PSA_SUCCESS) {
        printf("Periph Verify hash failed: %ld\n", status);
        return;
    }

    puts("ECDSA Periph Success");
}

int main(void)
{
    _test_init();
    psa_crypto_init();
    ecdsa_periph();

#ifdef TEST_STACK
    ps();
#endif
    return 0;
}
