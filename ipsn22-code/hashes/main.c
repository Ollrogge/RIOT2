#include <stdio.h>
#include <stdint.h>

#include "psa/crypto.h"

#ifdef TEST_STACK
#include "ps.h"
#endif

#include "periph/gpio.h"
gpio_t external_gpio = GPIO_PIN(1, 8);
gpio_t internal_gpio = GPIO_PIN(1, 7);

const uint8_t SHA256_MSG[] = {  0x09, 0xfc, 0x1a, 0xcc, 0xc2, 0x30, 0xa2, 0x05,
                                0xe4, 0xa2, 0x08, 0xe6, 0x4a, 0x8f, 0x20, 0x42,
                                0x91, 0xf5, 0x81, 0xa1, 0x27, 0x56, 0x39, 0x2d,
                                0xa4, 0xb8, 0xc0, 0xcf, 0x5e, 0xf0, 0x2b, 0x95};
const size_t SHA256_MSG_LEN = 32;

const uint8_t SHA256_DIG[] = {  0x4f, 0x44, 0xc1, 0xc7, 0xfb, 0xeb, 0xb6, 0xf9,
                                0x60, 0x18, 0x29, 0xf3, 0x89, 0x7b, 0xfd, 0x65,
                                0x0c, 0x56, 0xfa, 0x07, 0x84, 0x4b, 0xe7, 0x64,
                                0x89, 0x07, 0x63, 0x56, 0xac, 0x18, 0x86, 0xa4};
const size_t SHA256_DIG_LEN = 32;

const uint8_t SHA512_MSG[] = {  0x8c, 0xcb, 0x08, 0xd2, 0xa1, 0xa2, 0x82, 0xaa,
                                0x8c, 0xc9, 0x99, 0x02, 0xec, 0xaf, 0x0f, 0x67,
                                0xa9, 0xf2, 0x1c, 0xff, 0xe2, 0x80, 0x05, 0xcb,
                                0x27, 0xfc, 0xf1, 0x29, 0xe9, 0x63, 0xf9, 0x9d};
const size_t SHA512_MSG_LEN = 32;

const uint8_t SHA512_DIG[] = {  0x45, 0x51, 0xde, 0xf2, 0xf9, 0x12, 0x73, 0x86,
                                0xee, 0xa8, 0xd4, 0xda, 0xe1, 0xea, 0x8d, 0x8e,
                                0x49, 0xb2, 0xad, 0xd0, 0x50, 0x9f, 0x27, 0xcc,
                                0xbc, 0xe7, 0xd9, 0xe9, 0x50, 0xac, 0x7d, 0xb0,
                                0x1d, 0x5b, 0xca, 0x57, 0x9c, 0x27, 0x1b, 0x9f,
                                0x2d, 0x80, 0x67, 0x30, 0xd8, 0x8f, 0x58, 0x25,
                                0x2f, 0xd0, 0xc2, 0x58, 0x78, 0x51, 0xc3, 0xac,
                                0x8a, 0x0e, 0x72, 0xb4, 0xe1, 0xdc, 0x0d, 0xa6};
const size_t SHA512_DIG_LEN = 64;

static void _test_init(void)
{
    gpio_init(external_gpio, GPIO_OUT);
    gpio_init(internal_gpio, GPIO_OUT);

    gpio_set(external_gpio);
    gpio_clear(internal_gpio);
}

static void hashes_sha256(void)
{
    psa_status_t status = PSA_ERROR_DOES_NOT_EXIST;
    uint8_t result[SHA256_DIG_LEN];
    size_t hash_length;

    gpio_clear(external_gpio);
    status = psa_hash_compute(PSA_ALG_SHA_256, SHA256_MSG, SHA256_MSG_LEN, result, sizeof(result), &hash_length);
    gpio_set(external_gpio);
    if (status != PSA_SUCCESS || hash_length != SHA256_DIG_LEN) {
        printf("SHA 256 failed: %ld\n", status);
        return;
    }
    puts("SHA 256 Success");
}

#ifdef MULTIPLE_BACKENDS
static void hashes_sha512(void)
{
    psa_status_t status = PSA_ERROR_DOES_NOT_EXIST;
    uint8_t result[SHA512_DIG_LEN];
    size_t hash_length;

    gpio_clear(external_gpio);
    status = psa_hash_compute(PSA_ALG_SHA_512, SHA512_MSG, SHA512_MSG_LEN, result, sizeof(result), &hash_length);
    gpio_set(external_gpio);
    if (status != PSA_SUCCESS || hash_length != SHA512_DIG_LEN) {
        printf("SHA 512 failed: %ld\n", status);
        return;
    }
    puts("SHA 512 Success");
}
#endif

int main(void)
{
    _test_init();
    hashes_sha256();
#ifdef MULTIPLE_BACKENDS
    hashes_sha512();
#endif

#ifdef TEST_STACK
    ps();
#endif
    return 0;
}