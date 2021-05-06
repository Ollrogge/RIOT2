/*
 * Copyright (C) 2021 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     sys_psa_crypto
 * @{
 *
 * @file
 * @brief       Context definitions for PSA Crypto
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#ifndef CRYPTO_CONTEXT_H
#define CRYPTO_CONTEXT_H

#if IS_ACTIVE(CONFIG_PERIPH_HASHES)
#include "periph_hashes.h"
#endif
#if IS_ACTIVE(CONFIG_MODULE_CRYPTOAUTHLIB_HASHES)
#include "atca_hashes.h"
#endif

#include "psa/builtin_hashes.h"

#endif /* CRYPTO_CONTEXT_H */
