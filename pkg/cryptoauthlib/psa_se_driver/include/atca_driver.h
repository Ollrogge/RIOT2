#include "psa/crypto_se_driver.h"

#include "atca_key_management.h"
#include "atca_cipher.h"

const psa_drv_se_t atca_methods = {
    PSA_DRV_SE_HAL_VERSION,
    0,
    NULL,
    &atca_key_management,
    NULL,
    &atca_cipher,
    NULL,
    NULL,
    NULL
};