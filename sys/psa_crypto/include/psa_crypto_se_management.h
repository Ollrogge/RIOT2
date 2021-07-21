#ifndef PSA_CRYPTO_SE_MANAGEMENT_H
#define PSA_CRYPTO_SE_MANAGEMENT_H

#include "psa/crypto.h"
#include "psa_crypto_se_driver.h"

#if IS_ACTIVE(CONFIG_PSA_MULTIPLE_SECURE_ELEMENTS)
#define PSA_MAX_SE_COUNT    (PSA_KEY_LOCATION_SECONDARY_SE_MAX - PSA_KEY_LOCATION_SECONDARY_SE_MIN)
#else
#define PSA_MAX_SE_COUNT (PSA_KEY_LOCATION_PRIMARY_SECURE_ELEMENT)
#endif

typedef struct
{
    uint8_t persistent_data[PSA_MAX_PERSISTENT_DATA_SIZE];
    size_t persistent_data_size;
    uintptr_t transient_data;
} psa_drv_se_internal_context_t;

struct psa_se_drv_data_s
{
    psa_key_location_t location;
    const psa_drv_se_t *methods;
    union
    {
        psa_drv_se_internal_context_t internal;
        psa_drv_se_context_t context;
    } u;
};

typedef struct psa_se_drv_data_s psa_se_drv_data_t;

#if !IS_ACTIVE(CONFIG_PSA_MULTIPLE_SECURE_ELEMENTS)
psa_se_drv_data_t *psa_get_se_driver_data(psa_key_lifetime_t lifetime);
#endif

int psa_get_se_driver(  psa_key_lifetime_t lifetime,
                        const psa_drv_se_t **p_methods,
                        psa_drv_se_context_t **p_drv_context);

const psa_drv_se_t *psa_get_se_driver_methods(const psa_se_drv_data_t *driver);
psa_drv_se_context_t *psa_get_se_drv_context(psa_se_drv_data_t *driver);

psa_status_t psa_find_free_se_slot( const psa_key_attributes_t *attributes,
                                    psa_key_creation_method_t method,
                                    psa_se_drv_data_t *driver,
                                    psa_key_slot_number_t *slot_number);
psa_status_t psa_destroy_se_key(psa_se_drv_data_t *driver,
                                psa_key_slot_number_t slot_number);
psa_status_t psa_load_se_persistent_data(const psa_se_drv_data_t *driver);
psa_status_t psa_save_se_persistent_data(const psa_se_drv_data_t *driver);
psa_status_t psa_destroy_se_persistent_data(psa_key_location_t location);

typedef struct
{
    uint8_t slot_number[sizeof(psa_key_slot_number_t)];
} psa_se_key_data_storage_t;

#endif /* CRYPTO_SE_MANAGEMENT_H */
