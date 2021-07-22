#include "atca_params.h"
#include "psa/crypto.h"
#include "psa_crypto_se_driver.h"

#define AES_ECB_128_BLOCK_SIZE  (16)
#define AES_128_KEY_SIZE        (16)

static psa_status_t atca_to_psa_error(ATCA_STATUS error)
{
    switch(error) {
        case ATCA_NOT_LOCKED:
        case ATCA_EXECUTION_ERROR:
        case ATCA_FUNC_FAIL:
            return PSA_ERROR_BAD_STATE;
        case ATCA_WAKE_FAILED:
        case ATCA_RX_FAIL:
        case ATCA_RX_NO_RESPONSE:
        case ATCA_TX_TIMEOUT:
        case ATCA_RX_TIMEOUT:
        case ATCA_TOO_MANY_COMM_RETRIES:
        case ATCA_COMM_FAIL:
        case ATCA_TIMEOUT:
        case ATCA_TX_FAIL:
            return PSA_ERROR_COMMUNICATION_FAILURE;
        case ATCA_RX_CRC_ERROR:
        case ATCA_STATUS_CRC:
            return PSA_ERROR_DATA_CORRUPT;
        case ATCA_SMALL_BUFFER:
            return PSA_ERROR_BUFFER_TOO_SMALL;
        case ATCA_BAD_OPCODE:
        case ATCA_BAD_PARAM:
        case ATCA_INVALID_SIZE:
        case ATCA_INVALID_ID:
            return PSA_ERROR_INVALID_ARGUMENT;
        case ATCA_UNIMPLEMENTED:
            return PSA_ERROR_NOT_SUPPORTED;
        default:
            return PSA_ERROR_GENERIC_ERROR;
    }
}

/* Secure Element Cipher Functions */

psa_status_t atca_cipher_setup( psa_drv_se_context_t *drv_context,
                                void *op_context,
                                psa_key_slot_number_t key_slot,
                                psa_algorithm_t algorithm,
                                psa_encrypt_or_decrypt_t direction)
{
    ATCAIfaceCfg *cfg = (ATCAIfaceCfg *) drv_context->drv_data;

    /* Only device type ATECC608 supports AES operations */
    if (cfg->devtype != ATECC608) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* This implementation is for demonstration and currently only supports AES ECB encryption */
    if (algorithm != PSA_ALG_ECB_NO_PADDING || direction != PSA_CRYPTO_DRIVER_ENCRYPT) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* Store key slot number in operation context for key access in cipher operations */
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
    ATCA_STATUS status;
    ATCADevice dev = NULL;
    ATCAIfaceCfg *cfg = (ATCAIfaceCfg *) drv_context->drv_data;
    size_t offset;

    if (cfg->devtype != ATECC608) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (algorithm != PSA_ALG_ECB_NO_PADDING || direction != PSA_CRYPTO_DRIVER_ENCRYPT) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (input_size % AES_ECB_128_BLOCK_SIZE != 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Initialize device to pass to CryptoAuth library functions */
    status = atcab_init_ext(&dev, cfg);
    if (status != ATCA_SUCCESS) {
        return atca_to_psa_error(status);
    }

    offset = 0;
    do {
        status = calib_aes_encrypt(dev, key_slot, 0, p_input + offset, p_output + offset);
        if (status != ATCA_SUCCESS) {
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

    /*  This implementation is for demonstration purposes using an AES cipher operation and
        currently only returns the device's TEMPKEY-Register ID for key import.  */
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
    ATCA_STATUS status;
    ATCADevice dev = NULL;
    ATCAIfaceCfg *cfg = (ATCAIfaceCfg *) drv_context->drv_data;
    uint8_t buf_in[32] = {0};

    if (attributes->policy.alg != PSA_ALG_ECB_NO_PADDING) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (data_length != AES_128_KEY_SIZE) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    status = atcab_init_ext(&dev, cfg);
    if (status != ATCA_SUCCESS) {
        return atca_to_psa_error(status);
    }

    if (key_slot == ATCA_TEMPKEY_KEYID) {
        /* This implementation only uses the device's TEMPKEY Register for key import, which only accepts input sizes of 32 or 64 Bytes, so we copy a smaller key into a 32 Byte buffer that is padded with zeros */
        memcpy(buf_in, data, data_length);
        status = calib_nonce_load(dev, NONCE_MODE_TARGET_TEMPKEY, buf_in, sizeof(buf_in));

        if (status != ATCA_SUCCESS) {
            return atca_to_psa_error(status);
        }
        *bits = PSA_BYTES_TO_BITS(data_length);

        return PSA_SUCCESS;
    }

    return PSA_ERROR_NOT_SUPPORTED;
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
    .key_management = &atca_key_management,
    .mac = NULL,
    .cipher = &atca_cipher,
    .aead = NULL,
    .asymmetric = NULL,
    .derivation = NULL
};
