#ifndef CRYPTO_SE_MANAGEMENT_H
#define CRYPTO_SE_MANAGEMENT_H

#include "crypto.h"
#include "crypto_se_driver.h"

typedef struct psa_se_drv_data_s psa_se_drv_data_t;

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
