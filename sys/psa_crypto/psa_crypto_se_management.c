#include "include/psa_crypto_se_management.h"
#include "include/psa_crypto_se_driver.h"

#include <stdio.h>

#if IS_ACTIVE(CONFIG_PSA_CRYPTO_SECURE_ELEMENT)

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

psa_se_drv_data_t *psa_get_se_driver_data(psa_key_lifetime_t lifetime)
{
    if (PSA_KEY_LIFETIME_GET_LOCATION(lifetime) == PSA_KEY_LOCATION_PRIMARY_SECURE_ELEMENT) {
        return &se_driver;
    }
    return NULL;
}

psa_status_t psa_register_se_driver(psa_key_location_t location, const psa_drv_se_t *methods)
{
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

    se_driver.location = location;
    se_driver.methods = methods;
    se_driver.u.internal.persistent_data_size = methods->persistent_data_size;

    return PSA_SUCCESS;
}
#endif

int psa_get_se_driver(  psa_key_lifetime_t lifetime,
                        const psa_drv_se_t **p_methods,
                        psa_drv_se_context_t **p_drv_context)
{
    psa_se_drv_data_t *driver = psa_get_se_driver_data(lifetime);
    if (p_methods != NULL) {
        *p_methods = (driver ? driver->methods : NULL);
    }
    if (p_drv_context != NULL) {
        *p_drv_context = (driver ? &driver->u.context : NULL);
    }
    return (driver != NULL);
}

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
    psa_status_t status;
    psa_key_location_t key_location = PSA_KEY_LIFETIME_GET_LOCATION(psa_get_key_lifetime(attributes));

    if (driver->location != key_location) {
        printf("Driver Location: %lx\nKey Location: %lx\n", driver->location, key_location);
        return PSA_ERROR_CORRUPTION_DETECTED;
    }

    if (driver->methods->key_management == NULL) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    psa_drv_se_allocate_key_t p_allocate = driver->methods->key_management->p_allocate;

    if (p_allocate == NULL) {
        return PSA_ERROR_NOT_SUPPORTED;
    }
    status = p_allocate(&driver->u.context, driver->u.internal.persistent_data, attributes, method, slot_number);

    return status;
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
    (void) driver;
    return PSA_ERROR_GENERIC_ERROR;
}

psa_status_t psa_save_se_persistent_data(const psa_se_drv_data_t *driver)
{
    (void) driver;
    return PSA_ERROR_GENERIC_ERROR;
}

psa_status_t psa_destroy_se_persistent_data(psa_key_location_t location)
{
    (void) location;
    return PSA_ERROR_GENERIC_ERROR;
}


#endif /* CONFIG_PSA_CRYPTO_SECURE_ELEMENT */
