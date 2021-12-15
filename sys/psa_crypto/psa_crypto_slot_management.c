#include "include/psa_crypto_slot_management.h"

typedef struct
{
    psa_key_slot_t key_slots[PSA_KEY_SLOT_COUNT];
} psa_global_data_t;

static psa_global_data_t global_data;

int psa_is_valid_key_id(psa_key_id_t id, int vendor_ok)
{
    if ((PSA_KEY_ID_USER_MIN <= id) &&
        (id <= PSA_KEY_ID_USER_MAX)) {
        return 1;
    }

    if (vendor_ok &&
        (PSA_KEY_ID_VENDOR_MIN <= id) &&
        (id <= PSA_KEY_ID_VENDOR_MAX)) {
        return 1;
    }

    return 0;
}

psa_status_t psa_wipe_key_slot(psa_key_slot_t *slot)
{
    memset(slot, 0, sizeof(*slot));
    return PSA_SUCCESS;
}

static psa_status_t psa_get_and_lock_key_slot_in_memory(psa_key_id_t id, psa_key_slot_t **p_slot)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
#if PSA_KEY_SLOT_COUNT
    size_t slot_index;
    psa_key_slot_t *slot = NULL;

    if (psa_key_id_is_volatile(id)) {
        slot = &global_data.key_slots[id - PSA_KEY_ID_VOLATILE_MIN];
        status = (slot->attr.id == id) ? PSA_SUCCESS : PSA_ERROR_DOES_NOT_EXIST;
    }
    else {
        if (!psa_is_valid_key_id(id, 1)) {
            return PSA_ERROR_INVALID_HANDLE;
        }

        for (slot_index = 0; slot_index < PSA_KEY_SLOT_COUNT; slot_index++) {
            slot = &global_data.key_slots[slot_index];
            if (slot->attr.id == id) {
                break;
            }
        }
        status = (slot_index < PSA_KEY_SLOT_COUNT) ? PSA_SUCCESS : PSA_ERROR_DOES_NOT_EXIST;
    }

    if (status == PSA_SUCCESS) {
        status = psa_lock_key_slot(slot);
        if (status == PSA_SUCCESS) {
            *p_slot = slot;
        }
    }
#endif
    (void) id;
    (void) p_slot;
    return status;
}

psa_status_t psa_get_and_lock_key_slot(psa_key_id_t id, psa_key_slot_t **p_slot)
{
    /* TODO validate ID */

    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    *p_slot = NULL;

    status = psa_get_and_lock_key_slot_in_memory(id, p_slot);
    if (status != PSA_ERROR_DOES_NOT_EXIST) {
        return status;
    }

    /* TODO: get persistent key from storage and load into slot */

    return status;
}

void psa_wipe_all_key_slots(void)
{
    for (int i = 0; i < PSA_KEY_SLOT_COUNT; i++) {
        psa_key_slot_t *slot = &global_data.key_slots[i];
        slot->lock_count = 1;
        psa_wipe_key_slot(slot);
    }
}

psa_status_t psa_get_empty_key_slot(psa_key_id_t *id, psa_key_slot_t **p_slot)
{
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
#if PSA_KEY_SLOT_COUNT
    psa_key_slot_t *selected_slot, *unlocked_persistent_slot;

    selected_slot = unlocked_persistent_slot = NULL;

    for (size_t i = 0; i < PSA_KEY_SLOT_COUNT; i++) {
        psa_key_slot_t *slot = &global_data.key_slots[i];
        if (!psa_key_slot_occupied(slot)) {
            selected_slot = slot;
            break;
        }
        if ((!PSA_KEY_LIFETIME_IS_VOLATILE(slot->attr.lifetime) &&
            (psa_key_slot_occupied(slot)))) {
            unlocked_persistent_slot = slot;
        }
    }

    if ((selected_slot == NULL) && (unlocked_persistent_slot != NULL)) {
        selected_slot = unlocked_persistent_slot;
        selected_slot->lock_count = 1;
        psa_wipe_key_slot(selected_slot);
    }

    if (selected_slot != NULL) {
        status = psa_lock_key_slot(selected_slot);
        if (status != PSA_SUCCESS) {
            *p_slot = NULL;
            *id = 0;
            return status;
        }
        *id = PSA_KEY_ID_VOLATILE_MIN + ((psa_key_id_t) (selected_slot - global_data.key_slots));
        *p_slot = selected_slot;

        return PSA_SUCCESS;
    }

    status = PSA_ERROR_INSUFFICIENT_MEMORY;
#endif
    *p_slot = NULL;
    *id = 0;
    return status;
}

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

    if (slot->lock_count > 0) {
        slot->lock_count--;
        return PSA_SUCCESS;
    }

    return PSA_ERROR_CORRUPTION_DETECTED;
}

psa_status_t psa_validate_key_location(psa_key_lifetime_t lifetime, psa_se_drv_data_t **p_drv)
{
    if (psa_key_lifetime_is_external(lifetime)) {
#if IS_ACTIVE(CONFIG_PSA_SECURE_ELEMENT)
        psa_se_drv_data_t *driver = psa_get_se_driver_data(lifetime);
        if (driver != NULL) {
            if (p_drv != NULL) {
                *p_drv = driver;
            }
            return PSA_SUCCESS;
        }
#else
        (void) p_drv;
#endif /* CONFIG_PSA_SECURE_ELEMENT */
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    else {
        (void) p_drv;
        return PSA_SUCCESS;
    }
}


psa_status_t psa_validate_key_persistence(psa_key_lifetime_t lifetime)
{
    if (PSA_KEY_LIFETIME_IS_VOLATILE(lifetime)) {
        return PSA_SUCCESS;
    }
    /* TODO: Implement persistent key storage */
    return PSA_ERROR_NOT_SUPPORTED;
}