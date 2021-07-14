// #include "include/atca_key_management.h"
#include "psa_se_driver/atca_driver.h"
#include "psa_se_driver/atca_common.h"
#include <stdio.h>
#define  AES_ECB_128_BLOCK_SIZE (16)
// /* Secure Element Cipher Functions */

psa_status_t atca_cipher_setup( psa_drv_se_context_t *drv_context,
                                void *op_context,
                                psa_key_slot_number_t key_slot,
                                psa_algorithm_t algorithm,
                                psa_encrypt_or_decrypt_t direction)
{
    (void) drv_context;
    (void) op_context;
    (void) key_slot;

    if (algorithm != PSA_ALG_ECB_NO_PADDING || direction != PSA_CRYPTO_DRIVER_ENCRYPT) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    ((psa_cipher_context_t*) op_context)->se_key_slot = key_slot;

    return PSA_SUCCESS;
}

psa_status_t atca_cipher_ecb(   psa_drv_se_context_t *drv_context,
                                psa_key_slot_number_t key_slot,
                                psa_algorithm_t algorithm,
                                psa_encrypt_or_decrypt_t direction,
                                const uint8_t *p_input,
                                size_t input_size,
                                uint8_t *p_output,
                                size_t output_size)
{
    (void) drv_context;
    ATCA_STATUS status;
    size_t offset;
    if (algorithm != PSA_ALG_ECB_NO_PADDING || direction != PSA_CRYPTO_DRIVER_ENCRYPT) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (input_size % AES_ECB_128_BLOCK_SIZE != 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    offset = 0;
    do {
        status = atcab_aes_encrypt(key_slot, 0, p_input + offset, p_output + offset);
        if (status != ATCA_SUCCESS) {
            printf("ATCA status: %x\n", status);
            return atca_to_psa_error(status);
        }

        offset += AES_ECB_128_BLOCK_SIZE;
    } while (offset < input_size);

    (void) output_size;
    return PSA_SUCCESS;
}

/* Secure Element Key Management Functions */

psa_status_t atca_allocate (
    psa_drv_se_context_t *drv_context,
    void *persistent_data,
    const psa_key_attributes_t *attributes,
    psa_key_creation_method_t method,
    psa_key_slot_number_t *key_slot)
{
    (void) drv_context;
    (void) persistent_data;
    (void) method;

    if (attributes->policy.alg != PSA_ALG_ECB_NO_PADDING) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* TODO: Look for empty key slot that can be used for desired algorithm */
    /* Temporarily use TempKey register to demonstrate functionality */
    *key_slot = (psa_key_slot_number_t) ATCA_TEMPKEY_KEYID;

    return PSA_SUCCESS;
}

psa_status_t atca_import (
    psa_drv_se_context_t *drv_context,
    psa_key_slot_number_t key_slot,
    const psa_key_attributes_t *attributes,
    const uint8_t *data,
    size_t data_length,
    size_t *bits)
{
    (void) drv_context;

    ATCA_STATUS status;
    uint8_t buf_in[32] = {0};

    if (attributes->policy.alg != PSA_ALG_ECB_NO_PADDING) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (key_slot == ATCA_TEMPKEY_KEYID) {
        memcpy(buf_in, data, data_length);
        status = atcab_nonce_load(NONCE_MODE_TARGET_TEMPKEY, buf_in, sizeof(buf_in));

        if (status != ATCA_SUCCESS) {
            return atca_to_psa_error(status);
        }
    }

    *bits = PSA_BYTES_TO_BITS(data_length);

    return PSA_SUCCESS;
}

static psa_drv_se_cipher_t atca_cipher = {
    .context_size = 0,
    .p_setup = atca_cipher_setup,
    .p_set_iv = NULL,
    .p_update = NULL,
    .p_finish = NULL,
    .p_abort = NULL,
    .p_ecb = atca_cipher_ecb
};

static psa_drv_se_key_management_t atca_key_management = {
    .p_allocate = atca_allocate,
    .p_validate_slot_number = NULL,
    .p_import = atca_import,
    .p_generate = NULL,
    .p_destroy = NULL,
    .p_export = NULL,
    .p_export_public = NULL
};

psa_drv_se_t atca_methods = {
    .hal_version = PSA_DRV_SE_HAL_VERSION,
    .persistent_data_size = 0,
    .p_init = NULL,
    .key_management = &atca_key_management,
    .mac = NULL,
    .cipher = &atca_cipher,
    .aead = NULL,
    .asymmetric = NULL,
    .derivation = NULL
};
