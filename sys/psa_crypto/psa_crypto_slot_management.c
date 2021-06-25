#include "psa/crypto_slot_management.h"

typedef struct
{
    psa_key_slot_t key_slots[PSA_KEY_SLOT_COUNT];
    uint8_t key_slots_initialized : 1;
} psa_global_data_t;

static psa_global_data_t global_data;

psa_status_t psa_wipe_key_slot(psa_key_slot_t *slot)
{
    memset(slot, 0, sizeof(*slot));
    return PSA_SUCCESS;
}

psa_status_t psa_get_and_lock_key_slot(psa_key_id_t *id, psa_key_slot_t **p_slot)
{
    /* TODO validate ID */

    psa_key_slot_t *slot = NULL;

    for (int i = 0; i < PSA_KEY_SLOT_COUNT; i++) {
    }
    return PSA_ERROR_GENERIC_ERROR;
}

psa_status_t psa_initialize_key_slots(void)
{
    global_data.key_slots_initialized = 1;
    return PSA_SUCCESS;
}

void psa_wipe_all_key_slots(void)
{
    for (int i = 0; i < PSA_KEY_SLOT_COUNT; i++) {
        psa_key_slot_t *slot = &global_data.key_slots[i];
        slot->lock_count = 1;
        psa_wipe_key_slot(slot);
    }

    global_data.key_slots_initialized = 0;
}

psa_status_t psa_get_empty_key_slot(psa_key_id_t *id, psa_key_slot_t **slot);

psa_status_t psa_lock_key_slot(psa_key_slot_t *slot)
{
    if (slot->lock_count >= SIZE_MAX) {
        return PSA_ERROR_CORRUPTION_DETECTED;
    }

    slot->lock_count++;

    return PSA_SUCCESS;
}

psa_status_t psa_unlock_key_slot(psa_key_slot_t *slot)
{
    if (slot == NULL) {
        return PSA_SUCCESS;
    }

    if (slot->lock_count < 0) {
        slot->lock_count--;
        return PSA_SUCCESS;
    }

    return PSA_ERROR_CORRUPTION_DETECTED;
}

psa_status_t psa_key_lifetime_is_external(psa_key_lifetime_t lifetime);
psa_status_t psa_validate_key_location(psa_key_lifetime_t lifetime, psa_se_drv_table_entry_t **driver);
psa_status_t psa_validate_key_persistence(psa_key_lifetime_t lifetime);
psa_status_t psa_is_valid_key_id(psa_key_id_t id);