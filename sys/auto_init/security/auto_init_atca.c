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

#define ENABLE_DEBUG 0
#include "debug.h"

#if IS_ACTIVE(CONFIG_MODULE_PSA_CRYPTO)
#include "psa_crypto_se_management.h"

extern psa_drv_se_t atca_methods;
#endif

#define ATCA_NUMOF (ARRAY_SIZE(atca_params))

void auto_init_atca(void)
{
    DEBUG("Auto Init ATCA");
    for (unsigned i = 0; i < ATCA_NUMOF; i++) {
        if (atcab_init((ATCAIfaceCfg *)&atca_params[i].cfg) != ATCA_SUCCESS) {
            LOG_ERROR("[auto_init_atca] error initializing cryptoauth device #%u\n", i);
            continue;
        }

#if IS_ACTIVE(CONFIG_MODULE_PSA_CRYPTO)
        DEBUG("Registering Driver");
        if (i >= PSA_MAX_SE_COUNT) {
            LOG_ERROR("[auto_init_atca] PSA Crypto – too many secure elements #%u\n", i + 1);
            continue;
        }

        if (psa_register_secure_element(atca_params[i].atca_loc, &atca_methods, (ATCAIfaceCfg *) &atca_params[i].cfg) != PSA_SUCCESS) {
            LOG_ERROR("[auto_init_atca] error registering cryptoauth PSA driver for device #%u\n", i);
            continue;
        }
#endif
    }
}
