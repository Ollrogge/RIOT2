#ifndef PSA_PERIPH_UTIL_H
#define PSA_PERIPH_UTIL_H

#include "psa/crypto.h"
#include "cryptocell_incl/crys_hash_error.h"

psa_status_t cc310_to_psa_error(CRYSError_t error);

#endif /* PSA_PERIPH_UTIL_H */