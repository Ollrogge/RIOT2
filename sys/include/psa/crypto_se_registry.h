#ifndef CRYPTO_SE_REGISTRY_H
#define CRYPTO_SE_REGISTRY_H

#include "crypto_se_management.h"

#define PSA_MAX_SE_LOCATION (255)
#define PSA_MAX_SE_DRIVERS  (4)

psa_status_t psa_init_all_se_drivers(void);
psa_se_drv_data_t *psa_get_se_driver_data(psa_key_lifetime_t lifetime);
int psa_get_se_driver(  psa_key_lifetime_t lifetime,
                        const psa_drv_se_t **p_methods,
                        psa_drv_se_context_t **p_drv_context);

#endif /* CRYPTO_SE_REGISTRY_H */
