#ifndef PSA_PERIPH_HASHES_COMMON_H
#define PSA_PERIPH_HASHES_COMMON_H

#include "psa/crypto.h"
#include "cryptocell_incl/crys_hash.h"

psa_status_t common_hash_setup( CRYS_HASHUserContext_t * ctx,
                                CRYS_HASH_OperationMode_t mode);

psa_status_t common_hash_update(CRYS_HASHUserContext_t * ctx,
                                const uint8_t * input,
                                size_t input_length);

psa_status_t common_hash_finish(CRYS_HASHUserContext_t * ctx,
                                uint8_t * hash);

#endif /* PSA_PERIPH_HASHES_COMMON_H */