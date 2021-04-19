#ifndef ATCA_HW_HASHES_H
#define ATCA_HW_HASHES_H

#include "cryptoauthlib.h"
#include "psa/psa_crypto_values.h"
#include "psa/psa_crypto_types.h"

typedef atca_sha256_ctx_t atca_hash_ctx_t;

psa_status_t atca_hash_setup(psa_hash_operation_t * operation,
                                           psa_algorithm_t alg);

psa_status_t atca_hash_update(psa_hash_operation_t * operation,
                             const uint8_t * input,
                             size_t input_length);

psa_status_t atca_hash_finish(psa_hash_operation_t * operation,
                             uint8_t * hash);

#endif