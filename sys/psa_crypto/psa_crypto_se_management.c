#include "psa/crypto_se_management.h"
#include "crypto_se_driver.h"

#if IS_ACTIVE(PSA_MULTIPLE_SE)
#include "psa/crypto_se_registry.h"
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

#if !IS_ACTIVE(PSA_MULTIPLE_SE)
static psa_se_drv_data_t se_driver;
#endif

const psa_drv_se_t *psa_get_se_driver_methods(const psa_se_drv_data_t *driver)
{
    return driver->methods;
}

psa_drv_se_context_t *psa_get_se_drv_context(psa_se_drv_data_t *driver)
{
    return &driver->u.context;
}

psa_status_t psa_find_free_se_slot( const psa_key_attributes_t *attributes,
                                    psa_key_creation_method_t method,
                                    psa_se_drv_data_t *driver,
                                    psa_key_slot_number_t *slot_number)
{
    return PSA_ERROR_GENERIC_ERROR;
}

psa_status_t psa_destroy_se_key(psa_se_drv_data_t *driver,
                                psa_key_slot_number_t slot_number)
{
    if (driver->methods->key_management == NULL ||
        driver->methods->key_management->p_destroy == NULL) {
            return PSA_ERROR_NOT_PERMITTED;
    }
    return driver->methods->key_management->p_destroy(&driver->u.context, driver->u.internal.persistent_data, slot_number);

    /* TODO: Store Persistent Data */
}

psa_status_t psa_init_se_driver(void)
{
    return se_driver.methods->p_init(&se_driver.u.context, se_driver.u.internal.persistent_data, se_driver.location);
}

psa_status_t psa_load_se_persistent_data(const psa_se_drv_data_t *driver)
{
    return PSA_ERROR_GENERIC_ERROR;
}

psa_status_t psa_save_se_persistent_data(const psa_se_drv_data_t *driver)
{
    return PSA_ERROR_GENERIC_ERROR;
}

psa_status_t psa_destroy_se_persistent_data(psa_key_location_t location)
{
    return PSA_ERROR_GENERIC_ERROR;
}
