#ifndef PSA_CRYPTO_SLOT_MANAGEMENT_H
#define PSA_CRYPTO_SLOT_MANAGEMENT_H

#include "psa/crypto.h"
#include "psa_crypto_se_management.h"

#define PSA_KEY_SLOT_COUNT       (32)

#define PSA_KEY_ID_VOLATILE_MIN (PSA_KEY_ID_VENDOR_MAX - PSA_KEY_SLOT_COUNT + 1)
#define PSA_KEY_ID_VOLATILE_MAX (PSA_KEY_ID_VENDOR_MAX)

typedef struct
{
    psa_key_attributes_t attr;
    size_t lock_count;
    struct key_data
    {
        uint8_t data[PSA_MAX_KEY_LENGTH];
        size_t bytes;
    } key;
} psa_key_slot_t;

static inline int psa_is_key_slot_occupied(psa_key_slot_t *slot)
{
    return (slot->attr.type != 0);
}

static inline int psa_is_key_slot_locked(psa_key_slot_t *slot)
{
    return (slot->lock_count > 0);
}

static inline psa_key_slot_number_t psa_key_slot_get_slot_number(psa_key_slot_t *slot)
{
    return *((psa_key_slot_number_t *)(slot->key.data));
}

psa_status_t psa_wipe_key_slot(psa_key_slot_t *slot);
psa_status_t psa_get_and_lock_key_slot(psa_key_id_t *id, psa_key_slot_t **slot);
psa_status_t psa_initialize_key_slots(void);
void psa_wipe_all_key_slots(void);
psa_status_t psa_get_empty_key_slot(psa_key_id_t *id, psa_key_slot_t **slot);
psa_status_t psa_lock_key_slot(psa_key_slot_t *slot);
psa_status_t psa_unlock_key_slot(psa_key_slot_t *slot);
psa_status_t psa_key_lifetime_is_external(psa_key_lifetime_t lifetime);
psa_status_t psa_validate_key_location(psa_key_lifetime_t lifetime, psa_se_drv_data_t **driver);
psa_status_t psa_validate_key_persistence(psa_key_lifetime_t lifetime);
psa_status_t psa_is_valid_key_id(psa_key_id_t id);

#endif /* CRYPTO_SLOT_MANAGEMENT_H */
