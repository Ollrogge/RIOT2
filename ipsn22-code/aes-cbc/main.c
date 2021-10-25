#include <stdio.h>
#include <stdint.h>

#include "periph/gpio.h"
#include "psa/crypto.h"

#ifdef TEST_STACK
#include "ps.h"
#endif

gpio_t external_gpio = GPIO_PIN(1, 8);
gpio_t internal_gpio = GPIO_PIN(1, 7);

static uint8_t PLAINTEXT[] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
};
static uint8_t PLAINTEXT_LEN = 32;
static uint8_t CBC_CIPHER_LEN = 32;

static void _test_init(void)
{
    gpio_init(external_gpio, GPIO_OUT);
    gpio_init(internal_gpio, GPIO_OUT);

    gpio_set(external_gpio);
    gpio_clear(internal_gpio);
}

static void cipher_aes_128(void)
{
    psa_status_t status = PSA_ERROR_DOES_NOT_EXIST;

    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_key_id_t key_id = 0;
    psa_key_usage_t usage = PSA_KEY_USAGE_ENCRYPT;

    size_t iv_size = PSA_CIPHER_IV_LENGTH(PSA_KEY_TYPE_AES, PSA_ALG_CBC_NO_PADDING);
    size_t combined_output_size = CBC_CIPHER_LEN + iv_size;

    uint8_t cipher_out[combined_output_size];
    size_t output_len = 0;

    psa_set_key_algorithm(&attr, PSA_ALG_CBC_NO_PADDING);
    psa_set_key_usage_flags(&attr, usage);
    psa_set_key_bits(&attr, 128);
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);

    gpio_clear(external_gpio);
    status = psa_generate_key(&attr, &key_id);
    gpio_set(external_gpio);
    if (status != PSA_SUCCESS) {
        printf("AES 128 Key Generation failed: %ld\n", status);
        return;
    }

    gpio_clear(external_gpio);
    status = psa_cipher_encrypt(key_id, PSA_ALG_CBC_NO_PADDING, PLAINTEXT, PLAINTEXT_LEN, cipher_out, combined_output_size, &output_len);
    gpio_set(external_gpio);
    if (status != PSA_SUCCESS) {
        printf("AES 128 CBC Encrypt failed: %ld\n", status);
        return;
    }
    puts("AES 128 CBC Success");
}
#ifdef MULTIPLE_BACKENDS
static void cipher_aes_256(void)
{
    psa_status_t status = PSA_ERROR_DOES_NOT_EXIST;

    psa_key_attributes_t attr = psa_key_attributes_init();
    psa_key_id_t key_id = 0;
    psa_key_usage_t usage = PSA_KEY_USAGE_ENCRYPT;

    size_t iv_size = PSA_CIPHER_IV_LENGTH(PSA_KEY_TYPE_AES, PSA_ALG_CBC_NO_PADDING);
    size_t combined_output_size = CBC_CIPHER_LEN + iv_size;

    uint8_t cipher_out[combined_output_size];
    size_t output_len = 0;

    psa_set_key_algorithm(&attr, PSA_ALG_CBC_NO_PADDING);
    psa_set_key_usage_flags(&attr, usage);
    psa_set_key_bits(&attr, 256);
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);

    gpio_clear(external_gpio);
    status = psa_generate_key(&attr, &key_id);
    gpio_set(external_gpio);
    if (status != PSA_SUCCESS) {
        printf("AES 128 Key Generation failed: %ld\n", status);
        return;
    }
    gpio_clear(external_gpio);
    status = psa_cipher_encrypt(key_id, PSA_ALG_CBC_NO_PADDING, PLAINTEXT, PLAINTEXT_LEN, cipher_out, combined_output_size, &output_len);
    gpio_set(external_gpio);
    if (status != PSA_SUCCESS) {
        printf("AES 128 CBC Encrypt failed: %ld\n", status);
        return;
    }
    puts("AES 256 CBC Success");
}
#endif

int main(void)
{
    _test_init();

    cipher_aes_128();
#ifdef MULTIPLE_BACKENDS
    cipher_aes_256();
#endif

#ifdef TEST_STACK
    ps();
#endif
    return 0;
}