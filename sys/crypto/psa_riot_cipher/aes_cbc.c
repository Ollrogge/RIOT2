#include "psa/crypto.h"
#include "crypto/modes/cbc.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

static psa_status_t cipher_to_psa_error(int error)
{
    switch(error) {
        case CIPHER_ERR_INVALID_KEY_SIZE:
        case CIPHER_ERR_INVALID_LENGTH:
        case CIPHER_ERR_BAD_CONTEXT_SIZE:
            return PSA_ERROR_INVALID_ARGUMENT;
        default:
            return PSA_ERROR_GENERIC_ERROR;
    }
}

static psa_status_t cbc_aes_common( cipher_t * ctx, const uint8_t * key_buffer, size_t key_buffer_size,
                                uint8_t * iv, const uint8_t * input, size_t input_length,
                                uint8_t * output, size_t * output_length)
{
    int ret = 0;
    ret = cipher_init(ctx, CIPHER_AES, key_buffer, key_buffer_size);
    if (ret != CIPHER_INIT_SUCCESS) {
        return cipher_to_psa_error(ret);
    }

    ret = cipher_encrypt_cbc(ctx, iv, input, input_length, output);
    if (ret <= 0) {
        return cipher_to_psa_error(ret);
    }
    *output_length = ret;
    return PSA_SUCCESS;
}

#if IS_ACTIVE(CONFIG_RIOT_CIPHER_AES_128_CBC)
psa_status_t psa_cipher_cbc_aes_128_encrypt(const psa_key_attributes_t *attributes,
                                            const uint8_t *key_buffer,
                                            size_t key_buffer_size,
                                            psa_algorithm_t alg,
                                            const uint8_t * input,
                                            size_t input_length,
                                            uint8_t * output,
                                            size_t output_size,
                                            size_t * output_length)
{
    DEBUG("RIOT AES 128 Cipher");
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_cipher_operation_t operation = psa_cipher_operation_init();
    size_t iv_length = 0;

    operation.iv_required = 1;
    operation.default_iv_length = PSA_CIPHER_IV_LENGTH(attributes->type, alg);
    output_length = 0;

    status = psa_cipher_generate_iv(&operation, output, operation.default_iv_length, &iv_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = cbc_aes_common(&operation.ctx.aes_128, key_buffer, key_buffer_size, output, input, input_length, output + operation.default_iv_length, output_length);

    (void) output_size;
    return status;
}
#endif

#if IS_ACTIVE(CONFIG_RIOT_CIPHER_AES_256_CBC)
psa_status_t psa_cipher_cbc_aes_256_encrypt(const psa_key_attributes_t *attributes,
                                            const uint8_t *key_buffer,
                                            size_t key_buffer_size,
                                            psa_algorithm_t alg,
                                            const uint8_t * input,
                                            size_t input_length,
                                            uint8_t * output,
                                            size_t output_size,
                                            size_t * output_length)
{
    DEBUG("RIOT AES 256 Cipher");
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_cipher_operation_t operation = psa_cipher_operation_init();
    size_t iv_length = 0;

    operation.iv_required = 1;
    operation.default_iv_length = PSA_CIPHER_IV_LENGTH(attributes->type, alg);
    output_length = 0;

    status = psa_cipher_generate_iv(&operation, output, operation.default_iv_length, &iv_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = cbc_aes_common(&operation.ctx.aes_256, key_buffer, key_buffer_size, output, input, input_length, output + operation.default_iv_length, output_length);

    (void) output_size;
    return status;
}
#endif
