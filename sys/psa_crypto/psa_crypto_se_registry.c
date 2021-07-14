#include "include/psa_crypto_se_registry.h"
#include "include/psa_crypto_se_driver.h"

#if IS_ACTIVE(PSA_MULTIPLE_SE)

static psa_se_drv_data_t driver_table[PSA_MAX_SE_DRIVERS];

psa_status_t psa_init_all_se_drivers(void)
{
    return PSA_ERROR_GENERIC_ERROR;
}

psa_se_drv_data_t *psa_get_se_driver_data(psa_key_lifetime_t lifetime)
{
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(lifetime);

    if (location == 0) {
        return NULL;
    }
    for (size_t i = 0; i < PSA_MAX_SE_DRIVERS; i++) {
        if (driver_table[i]->location == location) {
            return &driver_table[i];
        }
    }
    return NULL;
}

psa_status_t psa_init_all_se_drivers(void)
{
    for (size_t i = 0; i < PSA_MAX_SE_DRIVERS; i++){
        psa_se_drv_data_t *driver = &driver_table[i];
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
}

psa_status_t psa_register_se_driver(psa_key_location_t location,
                                    const psa_drv_se_t *methods)
{
    size_t i;
    psa_status_t status;

    if (methods->hal_version != PSA_DRV_SE_HAL_VERSION) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (location == PSA_KEY_LOCATION_LOCAL_STORAGE) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    if (location > PSA_MAX_SE_LOCATION) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    if (methods->persistent_data_size > PSA_MAX_PERSISTENT_DATA_SIZE) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    for (i = 0; i < PSA_MAX_SE_DRIVERS; i++) {
        if (driver_table[i].location == 0) {
            break;
        }
        if (driver_table[i].location == location) {
            return PSA_ERROR_ALREADY_EXISTS;
        }
    }

    if (i == PSA_MAX_SE_DRIVERS) {
        return PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    driver_table[i].location = location;
    driver_table[i].methods = methods;
    driver_table[i].u.internal.persistent_data_size = methods->persistent_data_size;

    /* TODO: Load Persistent data if persistent_data_size != 0 */

    return PSA_SUCCESS;
}

#endif /* PSA_MULTIPLE_SE */