#ifndef PSA_CRYPTO_TYPES_H
#define PSA_CRYPTO_TYPES_H

#include <stdint.h>

typedef /* implementation-defined type */ uint32_t psa_aead_operation_t;
typedef uint32_t psa_algorithm_t;
typedef /* implementation-defined type */ uint32_t psa_cipher_operation_t;
typedef uint8_t psa_dh_family_t;
typedef uint8_t psa_ecc_family_t;
typedef /* implementation-defined type */ uint32_t psa_key_attributes_t;
typedef /* implementation-defined type */ uint32_t psa_key_derivation_operation_t;
typedef uint16_t psa_key_derivation_step_t;
typedef uint32_t psa_key_id_t;
typedef uint32_t psa_key_lifetime_t;
typedef uint32_t psa_key_location_t;
typedef uint8_t psa_key_persistence_t;
typedef uint16_t psa_key_type_t;
typedef uint32_t psa_key_usage_t;
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


#endif /* PSA_CRYPTO_TYPES_H */
