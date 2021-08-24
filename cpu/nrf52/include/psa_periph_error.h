#ifndef PSA_PERIPH_UTIL_H
#define PSA_PERIPH_UTIL_H

#include "psa/crypto.h"
#include "cryptocell_incl/crys_hash_error.h"
#include "cryptocell_incl/ssi_aes_error.h"

psa_status_t CRYS_to_psa_error(CRYSError_t error);
psa_status_t SaSi_to_psa_error(SaSiStatus error);

#endif /* PSA_PERIPH_UTIL_H */
