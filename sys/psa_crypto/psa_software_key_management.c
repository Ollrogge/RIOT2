#include "include/psa_software_key_management.h"
#include "psa/crypto.h"

static int key_type_is_raw_bytes( psa_key_type_t type )
{
    return( PSA_KEY_TYPE_IS_UNSTRUCTURED( type ) );
}

static psa_status_t psa_validate_unstructured_key_bit_size(psa_key_type_t type, size_t bits)
{
    switch(type) {
#if IS_ACTIVE(CONFIG_MODULE_PSA_SOFTWARE_CIPHER)
        case PSA_KEY_TYPE_AES:
            if (bits != 128 && bits != 192 && bits != 256)
                return PSA_ERROR_INVALID_ARGUMENT;
            break;
#endif
#if IS_ACTIVE(CONFIG_TINYCRYPT_CIPHER)
        case PSA_KEY_TYPE_AES:
            if (bits != 128)
                return PSA_ERROR_INVALID_ARGUMENT;
            break;
#endif
    default:
        (void) bits;
        return PSA_ERROR_NOT_SUPPORTED;
    }
    return PSA_SUCCESS;
}

psa_status_t psa_software_import_key(const psa_key_attributes_t *attributes,
                                    const uint8_t *data, size_t data_length,
                                    uint8_t *key_buffer, size_t key_buffer_size,
                                    size_t *key_buffer_length, size_t *bits)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_type_t type = attributes->type;

    if (data_length == 0) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (key_type_is_raw_bytes(type)) {
        *bits = PSA_BYTES_TO_BITS(data_length);

        if (*bits > PSA_MAX_KEY_BITS) {
            return PSA_ERROR_NOT_SUPPORTED;
        }
        status = psa_validate_unstructured_key_bit_size(type, *bits);
        if (status != PSA_SUCCESS) {
            return status;
        }

        memcpy(key_buffer, data, data_length);
        *key_buffer_length = data_length;
        (void) key_buffer_size;

        return PSA_SUCCESS;
    }
    return status;
}