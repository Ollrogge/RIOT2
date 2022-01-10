#ifndef PSA_CRYPTO_SLOT_MANAGEMENT_H
#define PSA_CRYPTO_SLOT_MANAGEMENT_H

#include "psa/crypto.h"
#include "psa_crypto_se_management.h"

#define PSA_KEY_SLOT_COUNT       (CONFIG_PSA_KEY_SLOT_COUNT)

#define PSA_KEY_ID_VOLATILE_MIN (PSA_KEY_ID_VENDOR_MIN)
#define PSA_KEY_ID_VOLATILE_MAX (PSA_KEY_ID_VENDOR_MIN + PSA_KEY_SLOT_COUNT)

/**
 * @brief Structure of a virtual key slot in local memory.
 *
 * A slot contains key attributes, a lock count and the key_data structure.
 * Key_data consists of the size of the stored key in bytes and a uint8_t data array large enough
 * to store the largest key used in the current build.
 * Keys can be either symmetric or asymmetric and are handled differently depending on the type.
 */
typedef struct {
    psa_key_attributes_t attr;
    size_t lock_count;
    struct key_data {
        void * data; /*!< Contains symmetric raw key, OR slot number for symmetric key in case of SE, OR asymmetric key pair structure */
        size_t bytes; /*!< Contains actual size of symmetric key or size of asymmetric key pair  structure, TODO: Is there a better solution? */
        void * pubkey_data;
        size_t pubkey_bytes;
    } key;
} psa_key_slot_t;

void psa_init_key_slots(void);

void * psa_malloc(size_t s);

void psa_free(void *p);

/** Test whether a key identifier is a volatile key identifier.
 *
 * @param key_id    Key identifier to test.
 *
 * @return  1       The key identifier is a volatile key identifier.
 *          0       The key identifier is not a volatile key identifier.
 */
static inline int psa_key_id_is_volatile(psa_key_id_t key_id)
{
    return ((key_id >= PSA_KEY_ID_VOLATILE_MIN) &&
            (key_id <= PSA_KEY_ID_VOLATILE_MAX));
}

static inline int psa_key_slot_occupied(psa_key_slot_t *slot)
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

static inline psa_status_t psa_key_lifetime_is_external(psa_key_lifetime_t lifetime)
{
    return (PSA_KEY_LIFETIME_GET_LOCATION(lifetime) != PSA_KEY_LOCATION_LOCAL_STORAGE);
}

psa_status_t psa_wipe_key_slot(psa_key_slot_t *slot);
psa_status_t psa_get_and_lock_key_slot(psa_key_id_t id, psa_key_slot_t **slot);
void psa_wipe_all_key_slots(void);
psa_status_t psa_get_empty_key_slot(psa_key_id_t *id, psa_key_slot_t **slot);
psa_status_t psa_lock_key_slot(psa_key_slot_t *slot);
psa_status_t psa_unlock_key_slot(psa_key_slot_t *slot);
psa_status_t psa_validate_key_location(psa_key_lifetime_t lifetime, psa_se_drv_data_t **driver);
psa_status_t psa_validate_key_persistence(psa_key_lifetime_t lifetime);
int psa_is_valid_key_id(psa_key_id_t id, int vendor_ok);

#endif /* CRYPTO_SLOT_MANAGEMENT_H */
