#ifndef ATCA_KEY_MANAGEMENT_H
#define ATCA_KEY_MANAGEMENT_H

#include "psa/crypto_se_driver.h"

const psa_drv_se_key_management_t atca_key_management = {
    atca_allocate,
    atca_validate_slot_number,
    atca_import,
    atca_generate,
    atca_destroy,
    atca_export,
    NULL
};

psa_status_t atca_allocate (
    psa_drv_se_context_t *drv_context,
    void *persistent_data,
    const psa_key_attributes_t *attributes,
    psa_key_creation_method_t method,
    psa_key_slot_number_t *key_slot);

psa_status_t atca_validate_slot_number (
    psa_drv_se_context_t *drv_context,
    void *persistent_data,
    const psa_key_attributes_t *attributes,
    psa_key_creation_method_t method,
    psa_key_slot_number_t key_slot);

psa_status_t atca_import (
    psa_drv_se_context_t *drv_context,
    psa_key_slot_number_t key_slot,
    const psa_key_attributes_t *attributes,
    const uint8_t *data,
    size_t data_length,
    size_t *bits);

psa_status_t atca_generate (
    psa_drv_se_context_t *drv_context,
    psa_key_slot_number_t key_slot,
    const psa_key_attributes_t *attributes,
    uint8_t *pubkey, size_t pubkey_size, size_t *pubkey_length);

psa_status_t atca_destroy (
    psa_drv_se_context_t *drv_context,
    void *persistent_data,
    psa_key_slot_number_t key_slot);

psa_status_t atca_export (
    psa_drv_se_context_t *drv_context,
    psa_key_slot_number_t key,
    uint8_t *p_data,
    size_t data_size,
    size_t *p_data_length);

#endif /* ATCA_KEY_MANAGEMENT_H */
