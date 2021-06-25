#include "include/atca_key_management.h"

psa_status_t atca_allocate (
    psa_drv_se_context_t *drv_context,
    void *persistent_data,
    const psa_key_attributes_t *attributes,
    psa_key_creation_method_t method,
    psa_key_slot_number_t *key_slot)
{
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t atca_validate_slot_number (
    psa_drv_se_context_t *drv_context,
    void *persistent_data,
    const psa_key_attributes_t *attributes,
    psa_key_creation_method_t method,
    psa_key_slot_number_t key_slot)
{
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t atca_import (
    psa_drv_se_context_t *drv_context,
    psa_key_slot_number_t key_slot,
    const psa_key_attributes_t *attributes,
    const uint8_t *data,
    size_t data_length,
    size_t *bits)
{
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t atca_generate (
    psa_drv_se_context_t *drv_context,
    psa_key_slot_number_t key_slot,
    const psa_key_attributes_t *attributes,
    uint8_t *pubkey, size_t pubkey_size, size_t *pubkey_length)
{
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t atca_destroy (
    psa_drv_se_context_t *drv_context,
    void *persistent_data,
    psa_key_slot_number_t key_slot)
{
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t atca_export (
    psa_drv_se_context_t *drv_context,
    psa_key_slot_number_t key,
    uint8_t *p_data,
    size_t data_size,
    size_t *p_data_length)
{
    return PSA_ERROR_NOT_SUPPORTED;
}