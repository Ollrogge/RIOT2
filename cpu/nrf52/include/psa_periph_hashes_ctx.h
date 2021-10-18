/*
 * Copyright (C) 2021 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     sys_psa_crypto cpu_nrf52
 * @{
 *
 * @file
 * @brief       Function declarations and context definition for glue code for
 *              ARM Cryptocell driver support in PSA Crypto
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#ifndef PERIPH_HASHES_H
#define PERIPH_HASHES_H

#include <stdlib.h>

#include "cryptocell_incl/crys_hash.h"

#if IS_ACTIVE(CONFIG_PERIPH_HASHES_SHA1)
typedef CRYS_HASHUserContext_t psa_hashes_sha1_ctx_t;
#endif

#if IS_ACTIVE(CONFIG_PERIPH_HASHES_SHA224)
typedef CRYS_HASHUserContext_t psa_hashes_sha224_ctx_t;
#endif

#if IS_ACTIVE(CONFIG_PERIPH_HASHES_SHA256)
typedef CRYS_HASHUserContext_t psa_hashes_sha256_ctx_t;
#endif

#if IS_ACTIVE(CONFIG_PERIPH_HASHES_SHA512)
typedef CRYS_HASHUserContext_t psa_hashes_sha512_ctx_t;
#endif

#endif /* PERIPH_HASHES_H */
