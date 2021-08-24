#include "psa_periph_error.h"
#include "psa_periph_aes_common.h"
#include "cryptocell_incl/ssi_aes.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

psa_status_t psa_cipher_aes_cbc_encrypt(const psa_key_attributes_t *attributes,
                                        const uint8_t *key_buffer,
                                        size_t key_buffer_size,
                                        psa_algorithm_t alg,
                                        const uint8_t * input,
                                        size_t input_length,
                                        uint8_t * output,
                                        size_t output_size,
                                        size_t * output_length)
{
    (void) output_size;
    DEBUG("Periph AES Cipher");
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    size_t iv_length = 0;
    int ret;
    SaSiAesUserKeyData_t key;

    psa_cipher_operation_t operation = psa_cipher_operation_init();
    operation.iv_required = 1;
    operation.default_iv_length = PSA_CIPHER_IV_LENGTH(attributes->type, alg);

    uint8_t iv[operation.default_iv_length];

    status = common_aes_setup((SaSiAesUserContext_t *) &operation.ctx.aes, SASI_AES_ENCRYPT, SASI_AES_MODE_CBC, SASI_AES_PADDING_NONE);
    if (status != PSA_SUCCESS) {
        return status;
    }

    key.keySize = key_buffer_size;
    key.pKey = (uint8_t *) key_buffer;

    ret = SaSi_AesSetKey((SaSiAesUserContext_t *) &operation.ctx.aes, SASI_AES_USER_KEY, &key, sizeof(key));
    if (ret != SASI_OK) {
        return SaSi_to_psa_error(ret);
    }

    status = psa_cipher_generate_iv(&operation, iv, operation.default_iv_length, &iv_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    memcpy(output, iv, operation.default_iv_length);

    ret = SaSi_AesSetIv((SaSiAesUserContext_t *) &operation.ctx.aes, iv);
    if (ret != SASI_OK) {
        return SaSi_to_psa_error(ret);
    }

    status = common_aes_update((SaSiAesUserContext_t *) &operation.ctx.aes, input, input_length, output + operation.default_iv_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    *output_length = output_size;

    return PSA_SUCCESS;
}