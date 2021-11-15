#ifndef PSA_PERIPH_ECC_H
#define PSA_PERIPH_ECC_H

#include "cryptocell_incl/crys_ecpki_types.h"

#define PSA_MAX_ECC_PRIV_KEY_SIZE   (sizeof(CRYS_ECPKI_UserPrivKey_t))
#define PSA_MAX_ECC_PUB_KEY_SIZE    (sizeof(CRYS_ECPKI_UserPublKey_t))

#endif /* PSA_PERIPH_ECC_H */