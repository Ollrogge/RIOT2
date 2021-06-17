#include "psa/crypto_se_management.h"
#include "crypto_se_driver.h"

typedef struct
{
    void *persistent_data;
    size_t persistent_data_size;
    uintptr_t transient_data;
} psa_drv_se_internal_context_t;

struct psa_se_drv_table_entry_s
{
    psa_key_location_t location;
    const psa_drv_se_t *methods;
    union
    {
      psa_drv_se_internal_context_t internal;
      psa_drv_se_context_t context;
    } u;
};

#if IS_ACTIVE(PSA_MULTIPLE_SE)
static psa_se_drv_table_entry_t driver_table[PSA_MAX_SE_DRIVERS];
#else
static psa_se_drv_table_entry_t se_driver;
#endif

psa_se_drv_table_entry_t *psa_get_se_driver_entry(psa_key_lifetime_t lifetime)
{
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(lifetime);

    if (location == 0) {
        return NULL;
    }

#if IS_ACTIVE(PSA_MULTIPLE_SE)
    for (size_t i = 0; i < PSA_MAX_SE_DRIVERS; i++) {
        if (driver_table[i]->location == location) {
            return &driver_table[i];
        }
    }
#else
    if (se_driver.location == location) {
        return &se_driver;
    }
#endif /* PSA_MULTIPLE_SE */

    return NULL;
}

const psa_drv_se_t *psa_get_se_driver_methods(const psa_se_drv_table_entry_t *driver)
{
    return driver->methods;
}

psa_drv_se_context_t *psa_get_se_drv_context(psa_se_drv_table_entry_t *driver)
{
    return &driver->u.context;
}

int psa_get_se_driver(  psa_key_lifetime_t lifetime,
                        const psa_drv_se_t **p_methods,
                        psa_drv_se_context_t **p_drv_context)
{
    psa_se_drv_table_entry_t *driver = psa_get_se_driver_entry(lifetime);
    if (p_methods != NULL) {
        *p_methods = (driver ? driver->methods : NULL);
    }
    if (p_drv_context != NULL) {
        *p_drv_context = (driver ? &driver->u.context : NULL);
    }
    return (driver != NULL);
}

psa_status_t psa_destroy_se_key(psa_se_drv_table_entry_t *driver,
                                psa_key_slot_number_t slot_number)
{
    if (driver->methods->key_management == NULL ||
        driver->methods->key_management->p_destroy == NULL) {
            return PSA_ERROR_NOT_PERMITTED;
    }
    return driver->methods->key_management->p_destroy(&driver->u.context, driver->u.internal.persistent_data, slot_number);

    /* TODO: Store Persistent Data */
}

psa_status_t psa_init_all_se_drivers(void)
{
#if IS_ACTIVE(PSA_MULTIPLE_SE)
    for (size_t i = 0; i < PSA_MAX_SE_DRIVERS; i++){
        psa_se_drv_table_entry_t *driver = &driver_table[i];
        if (driver->location == 0) {
            continue;
        }
        const psa_drv_se_t *methods = psa_get_se_driver_methods(driver);
        if (methods->p_init != NULL) {
            psa_status_t status = methods->p_init(&driver->u.context, driver->u.internal.persistent_data, driver->location);
            if (status != PSA_SUCCESS) {
                return status;
            }
        }
        return PSA_SUCCESS;
    }
#else
    return se_driver.methods->p_init(&se_driver.u.context, se_driver.u.internal.persistent_data, se_driver.location);
#endif
}

#if IS_ACTIVE(PSA_MULTIPLE_SE)
#endif

psa_status_t psa_register_se_driver(psa_key_location_t location,
                                    const psa_drv_se_t *methods)
{
    size_t i;
    psa_status_t status;

    if( methods->hal_version != PSA_DRV_SE_HAL_VERSION )
        return( PSA_ERROR_NOT_SUPPORTED );


}