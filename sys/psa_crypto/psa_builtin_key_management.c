#include "psa/crypto.h"

static int key_type_is_raw_bytes( psa_key_type_t type )
{
    return PSA_KEY_TYPE_IS_UNSTRUCTURED(type);
}

static psa_status_t psa_validate_unstructured_key_bit_size(psa_key_type_t type, size_t bits)
{
    switch(type) {
        case PSA_KEY_TYPE_AES:
            if (bits != 128 && bits != 192 && bits != 256)
                return PSA_ERROR_INVALID_ARGUMENT;
            break;
    default:
        (void) bits;
        return PSA_ERROR_NOT_SUPPORTED;
    }
    return PSA_SUCCESS;
}

psa_status_t psa_builtin_import_key(const psa_key_attributes_t *attributes,
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

psa_status_t psa_builtin_generate_key(const psa_key_attributes_t *attributes, uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_type_t type = attributes->type;

    if (key_type_is_raw_bytes(type)) {
        status = psa_generate_random(key_buffer, key_buffer_size);
        if (status != PSA_SUCCESS) {
            return status;
        }
        *key_buffer_length = key_buffer_size;
    }
    else {
        (void) key_buffer;
        (void) key_buffer_size;
        (void) key_buffer_length;
        return PSA_ERROR_NOT_SUPPORTED;
    }
    return PSA_SUCCESS;
}
