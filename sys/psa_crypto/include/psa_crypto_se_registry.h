#ifndef PSA_CRYPTO_SE_REGISTRY_H
#define PSA_CRYPTO_SE_REGISTRY_H

#include "psa_crypto_se_management.h"

#define PSA_MAX_SE_DRIVERS  (4)

psa_status_t psa_init_all_se_drivers(void);
psa_se_drv_data_t *psa_get_se_driver_data(psa_key_lifetime_t lifetime);

#endif /* CRYPTO_SE_REGISTRY_H */
