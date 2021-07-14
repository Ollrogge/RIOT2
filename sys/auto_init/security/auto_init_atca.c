/*
 * Copyright (C) 2019 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     sys_auto_init
 * @{
 * @file
 * @brief       Initializes cryptoauth devices
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 * @}
 */

#include "log.h"
#include "atca.h"
#include "atca_params.h"
#include "kernel_defines.h"

#define ENABLE_DEBUG 1
#include "debug.h"

#if IS_ACTIVE(CONFIG_MODULE_PSA_CRYPTO)
#include "psa_se_driver/atca_driver.h"
#include "psa_crypto_se_management.h"
#endif

#define ATCA_NUMOF (ARRAY_SIZE(atca_params))

void auto_init_atca(void)
{
    DEBUG("Auto Init ATCA");
    for (unsigned i = 0; i < ATCA_NUMOF; i++) {
        if (atcab_init((ATCAIfaceCfg *)&atca_params[i]) != ATCA_SUCCESS) {
            LOG_ERROR("[auto_init_atca] error initializing cryptoauth device #%u\n", i);
            continue;
        }

#if IS_ACTIVE(CONFIG_MODULE_PSA_CRYPTO)
        DEBUG("Registering Driver");
        psa_key_location_t location = i + 1; /* Lowest possible SE location value is 1 */
        if (psa_register_se_driver(location, &atca_methods) != PSA_SUCCESS) {
            LOG_ERROR("[auto_init_atca] error registering cryptoauth PSA driver for device #%u\n", i);
            continue;
        }
#endif
    }
}
