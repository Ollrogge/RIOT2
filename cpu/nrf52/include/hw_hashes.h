#ifndef CC_HASHES_H
#define CC_HASHES_H 

#include <stdlib.h>
#include "psa/psa_crypto_values.h"
#include "psa/psa_crypto_types.h"

psa_status_t cc_hash_setup(psa_hash_operation_t * operation,
                                           psa_algorithm_t alg);

psa_status_t cc_hash_update(psa_hash_operation_t * operation,
                             const uint8_t * input,
                             size_t input_length);

psa_status_t cc_hash_finish(psa_hash_operation_t * operation,
                             uint8_t * hash);

#endif /* CC_HASHES_H */
