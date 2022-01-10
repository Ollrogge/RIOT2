#include "atca_params.h"
#include "psa/crypto.h"
#include "psa_crypto_se_driver.h"

#define ENABLE_DEBUG    (1)
#include "debug.h"

#if TEST_TIME
#include "periph/gpio.h"
extern gpio_t internal_gpio;
#endif

#define AES_ECB_128_BLOCK_SIZE  (16)
#define AES_128_KEY_SIZE        (16)
#define ECC_P256_PUB_KEY_SIZE   (64)

#define ALG_IS_SUPPORTED(alg)   \
    (   (alg == PSA_ALG_ECB_NO_PADDING) || \
        (alg == PSA_ALG_ECDSA(PSA_ALG_SHA_256)) || \
        (alg == PSA_ALG_HMAC(PSA_ALG_SHA_256)))

#define KEY_SIZE_IS_SUPPORTED(size, type) \
    (   (type == PSA_KEY_TYPE_AES && size == AES_128_KEY_SIZE) || \
        (PSA_KEY_TYPE_IS_ECC(type) && size == (ECC_P256_PUB_KEY_SIZE + 1)) || \
        (type == PSA_KEY_TYPE_HMAC && size == 32))

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
    ATCADevice dev = (ATCADevice) drv_context->drv_data;

    /* Only device type ATECC608 supports AES operations */
    if (dev->mIface.mIfaceCFG->devtype != ATECC608) {
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
    ATCADevice dev = (ATCADevice) drv_context->drv_data;
    size_t offset;

    if (dev->mIface.mIfaceCFG->devtype != ATECC608) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (algorithm != PSA_ALG_ECB_NO_PADDING || direction != PSA_CRYPTO_DRIVER_ENCRYPT) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (input_size % AES_ECB_128_BLOCK_SIZE != 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    offset = 0;
    do {
        status = calib_aes_encrypt(dev, key_slot, 0, p_input + offset, p_output + offset);
        if (status != ATCA_SUCCESS) {
            DEBUG("ATCA Error: %d\n", status);
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
    if (!ALG_IS_SUPPORTED(attributes->policy.alg)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* TODO: Look for empty key slot that can be used for desired algorithm -> utilize driver persistent data */

    if (attributes->type == PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1)) {
        /* At the time of the implementation we are using an SE in which key slot 1 is configured for ECC private keys, so we return key slot nr. 1 */
        *key_slot = (psa_key_slot_number_t) 1;
    }
    else if (attributes->type == PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1)) {
        /* Slots 9-14 on device are configured to hold public keys */
        *key_slot = (psa_key_slot_number_t) 9;
    }
    else {
        /* Returns the device's TEMPKEY-Register ID for AES and temporary ECC Public Key import.  */
        *key_slot = (psa_key_slot_number_t) ATCA_TEMPKEY_KEYID;
    }

    (void) drv_context;
    (void) persistent_data;
    (void) method;

    return PSA_SUCCESS;
}

psa_status_t atca_import (  psa_drv_se_context_t *drv_context,
                            psa_key_slot_number_t key_slot,
                            const psa_key_attributes_t *attributes,
                            const uint8_t *data,
                            size_t data_length,
                            size_t *bits)
{
    ATCA_STATUS status;
    ATCADevice dev = (ATCADevice) drv_context->drv_data;

    uint8_t buf_in[32] = {0};

    if (!ALG_IS_SUPPORTED(attributes->policy.alg)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (!KEY_SIZE_IS_SUPPORTED(data_length, attributes->type)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (key_slot == ATCA_TEMPKEY_KEYID) {
        /* This implementation only uses the device's TEMPKEY Register for key import, which only accepts input sizes of 32 or 64 Bytes, so we copy a smaller key into a 32 Byte buffer that is padded with zeros */
        memcpy(buf_in, data, data_length);
        status = calib_nonce_load(dev, NONCE_MODE_TARGET_TEMPKEY, buf_in, sizeof(buf_in));

        if (status != ATCA_SUCCESS) {
            DEBUG("ATCA Error: %d\n", status);
            return atca_to_psa_error(status);
        }
        *bits = PSA_BYTES_TO_BITS(data_length);

        return PSA_SUCCESS;
    }
    else if (PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY(attributes->type)) {

#if TEST_TIME
        gpio_set(internal_gpio);
        status = calib_write_pubkey(dev, key_slot, data + 1);
        gpio_clear(internal_gpio);
#else
        status = calib_write_pubkey(dev, key_slot, data + 1);
#endif
        if (status != ATCA_SUCCESS) {
            DEBUG("ATCA Error: %d\n", status);
            return atca_to_psa_error(status);
        }
        *bits = PSA_BYTES_TO_BITS(data_length);

        return PSA_SUCCESS;
    }

    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t atca_generate_key( psa_drv_se_context_t *drv_context,
                                psa_key_slot_number_t key_slot,
                                const psa_key_attributes_t *attributes,
                                uint8_t *pubkey, size_t pubkey_size, size_t *pubkey_length)
{
    ATCA_STATUS status;
    ATCADevice dev = (ATCADevice) drv_context->drv_data;

    if (!PSA_KEY_TYPE_IS_ECC(attributes->type)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (pubkey_size > PSA_EXPORT_PUBLIC_KEY_MAX_SIZE) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (pubkey != NULL) {
#if TEST_TIME
        gpio_set(internal_gpio);
        status = calib_genkey(dev, key_slot, &pubkey[1]);
        gpio_clear(internal_gpio);
#else
        /* The driver already exports the public key, in the correct format (uncompressed binary). We can just write the key into the pubkey buffer. First byte is reserved for format encoding (set below) */
        status = calib_genkey(dev, key_slot, &pubkey[1]);
#endif
    }
    else {
        status = calib_genkey(dev, key_slot, NULL);
    }

    if (status != ATCA_SUCCESS) {
        DEBUG("ATCA Error: %d\n", status);
        return atca_to_psa_error(status);
    }
    /* Set first byte of pubkey buffer to 0x04 to encode public key uncompressed binary format */
    pubkey[0] = 0x04;
    *pubkey_length = PSA_EXPORT_PUBLIC_KEY_OUTPUT_SIZE(attributes->type, attributes->bits);

    return PSA_SUCCESS;
}

psa_status_t atca_export_public_key(psa_drv_se_context_t *drv_context,
                                    psa_key_slot_number_t key_slot,
                                    uint8_t *p_data,
                                    size_t data_size,
                                    size_t *p_data_length)
{
    ATCA_STATUS status;
    ATCADevice dev = (ATCADevice) drv_context->drv_data;

    if (data_size < ECC_P256_PUB_KEY_SIZE) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

    status = calib_get_pubkey(dev, key_slot, &p_data[1]);
    if (status != ATCA_SUCCESS) {
        DEBUG("ATCA Error: %d\n", status);
        return atca_to_psa_error(status);
    }

    p_data[0] = 0x04;
    *p_data_length = ECC_P256_PUB_KEY_SIZE + 1;

    return PSA_SUCCESS;
}

psa_status_t atca_sign( psa_drv_se_context_t *drv_context,
                        psa_key_slot_number_t key_slot,
                        psa_algorithm_t alg,
                        const uint8_t *p_hash,
                        size_t hash_length,
                        uint8_t *p_signature,
                        size_t signature_size,
                        size_t *p_signature_length)
{
    ATCA_STATUS status;
    ATCADevice dev = (ATCADevice) drv_context->drv_data;

    if (alg != PSA_ALG_ECDSA(PSA_ALG_SHA_256)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if ((signature_size != ECC_P256_PUB_KEY_SIZE) || (hash_length != 32)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

#if TEST_TIME
    gpio_set(internal_gpio);
    status = calib_sign(dev, key_slot, p_hash, p_signature);
    gpio_clear(internal_gpio);
#else
    status = calib_sign(dev, key_slot, p_hash, p_signature);
#endif

    if (status != ATCA_SUCCESS) {
        DEBUG("ATCA Error: %d\n", status);
        return atca_to_psa_error(status);
    }

    *p_signature_length = signature_size;
    return PSA_SUCCESS;
}

psa_status_t atca_verify(   psa_drv_se_context_t *drv_context,
                            psa_key_slot_number_t key_slot,
                            psa_algorithm_t alg,
                            const uint8_t *p_hash,
                            size_t hash_length,
                            const uint8_t *p_signature,
                            size_t signature_length)
{
    ATCA_STATUS status;
    ATCADevice dev = (ATCADevice) drv_context->drv_data;

    bool is_verified;

    /* We only support the operation on public key, if they're stored on a device. */
    if (alg != PSA_ALG_ECDSA(PSA_ALG_SHA_256)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if ((signature_length != ECC_P256_PUB_KEY_SIZE) || (hash_length != 32)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

#if TEST_TIME
    gpio_set(internal_gpio);
    status = calib_verify_stored(dev, p_hash, p_signature, key_slot, &is_verified);
    gpio_clear(internal_gpio);
#else
    status = calib_verify_stored(dev, p_hash, p_signature, key_slot, &is_verified);
#endif

    if (status != ATCA_SUCCESS) {
        DEBUG("ATCA Error: %d\n", status);
        return atca_to_psa_error(status);
    }

    return is_verified ? PSA_SUCCESS : PSA_ERROR_INVALID_SIGNATURE;
}

psa_status_t atca_generate_mac( psa_drv_se_context_t *drv_context,
                                const uint8_t *p_input,
                                size_t input_length,
                                psa_key_slot_number_t key_slot,
                                psa_algorithm_t alg,
                                uint8_t *p_mac,
                                size_t mac_size,
                                size_t *p_mac_length)
{
    ATCA_STATUS status;
    ATCADevice dev = (ATCADevice) drv_context->drv_data;

    if (!PSA_ALG_IS_HMAC(alg)) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (mac_size < 32) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

#if TEST_TIME
    gpio_set(internal_gpio);
    status = calib_sha_hmac(dev, p_input, input_length, key_slot, p_mac, SHA_MODE_TARGET_OUT_ONLY);
    gpio_clear(interal_gpio);
#else
    status = calib_sha_hmac(dev, p_input, input_length, key_slot, p_mac, SHA_MODE_TARGET_OUT_ONLY);
#endif
    if (status != ATCA_SUCCESS) {
        DEBUG("ATCA Error: %d\n", status);
        return atca_to_psa_error(status);
    }

    *p_mac_length = 32;

    return PSA_SUCCESS;
}

static psa_drv_se_mac_t atca_mac = {
    .context_size = 0,
    .p_setup = NULL,
    .p_update = NULL,
    .p_finish = NULL,
    .p_finish_verify = NULL,
    .p_abort = NULL,
    .p_mac = atca_generate_mac,
    .p_mac_verify = NULL,
};

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
    .p_generate = atca_generate_key,
    .p_destroy = NULL,
    .p_export = NULL,
    .p_export_public = atca_export_public_key
};

static psa_drv_se_asymmetric_t atca_asymmetric = {
    .p_sign = atca_sign,
    .p_verify = atca_verify,
    .p_encrypt = NULL,
    .p_decrypt = NULL
};

psa_drv_se_t atca_methods = {
    .hal_version = PSA_DRV_SE_HAL_VERSION,
    .persistent_data_size = 0,
    .p_init = NULL,
    .key_management = &atca_key_management,
    .mac = &atca_mac,
    .cipher = &atca_cipher,
    .aead = NULL,
    .asymmetric = &atca_asymmetric,
    .derivation = NULL
};
