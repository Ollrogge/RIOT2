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
 * @brief       General type definitions for PSA Crypto
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#ifndef PSA_CRYPTO_TYPES_H
#define PSA_CRYPTO_TYPES_H

#include <stdint.h>

typedef enum {
    PSA_CIPHER_ENCRYPT,
    PSA_CIPHER_DECRYPT
} cipher_operation_t;

/* These are all temporarily defined as some numeric type to prevent errors at compile time.*/

typedef /* implementation-defined type */ uint32_t psa_aead_operation_t;
typedef uint32_t psa_algorithm_t;

typedef uint8_t psa_dh_family_t;

/** The type of PSA elliptic curve family identifiers.
 *
 * The curve identifier is required to create an ECC key using the
 * PSA_KEY_TYPE_ECC_KEY_PAIR() or PSA_KEY_TYPE_ECC_PUBLIC_KEY()
 * macros.
 *
 * Values defined by this standard will never be in the range 0x80-0xff.
 * Vendors who define additional families must use an encoding in this range.
 */
typedef uint8_t psa_ecc_family_t;

typedef /* implementation-defined type */ uint32_t psa_key_derivation_operation_t;
typedef uint16_t psa_key_derivation_step_t;
typedef uint32_t psa_key_id_t;
typedef uint32_t psa_key_lifetime_t;
typedef uint32_t psa_key_location_t;
typedef uint8_t psa_key_persistence_t;
typedef uint16_t psa_key_type_t;
typedef uint32_t psa_key_usage_t;

/* The type used internally for key sizes.
 * Public interfaces use size_t, but internally we use a smaller type. */
typedef uint16_t psa_key_bits_t;

/* The maximum value of the type used to represent bit-sizes.
 * This is used to mark an invalid key size. */
#define PSA_KEY_BITS_TOO_LARGE          ((psa_key_bits_t) - 1)

/* The maximum size of a key in bits.
 * Currently defined as the maximum that can be represented, rounded down
 * to a whole number of bytes.
 * This is an uncast value so that it can be used in preprocessor
 * conditionals. */
#define PSA_MAX_KEY_BITS 0xfff8

typedef /* implementation-defined type */ uint32_t psa_mac_operation_t;
typedef int32_t psa_status_t;

/** The type of the state data structure for multipart hash operations.
 *
 * Before calling any function on a hash operation object, the application must
 * initialize it by any of the following means:
 * - Set the structure to all-bits-zero, for example:
 *   @code
 *   psa_hash_operation_t operation;
 *   memset(&operation, 0, sizeof(operation));
 *   @endcode
 * - Initialize the structure to logical zero values, for example:
 *   @code
 *   psa_hash_operation_t operation = {0};
 *   @endcode
 * - Initialize the structure to the initializer #PSA_HASH_OPERATION_INIT,
 *   for example:
 *   @code
 *   psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
 *   @endcode
 * - Assign the result of the function psa_hash_operation_init()
 *   to the structure, for example:
 *   @code
 *   psa_hash_operation_t operation;
 *   operation = psa_hash_operation_init();
 *   @endcode
 *
 * This is an implementation-defined struct. Applications should not
 * make any assumptions about the content of this structure except
 * as directed by the documentation of a specific implementation. */
typedef struct psa_hash_operation_s psa_hash_operation_t;

typedef struct psa_key_attributes_s psa_key_attributes_t;

typedef struct psa_cipher_operation_s psa_cipher_operation_t;

#endif /* PSA_CRYPTO_TYPES_H */
