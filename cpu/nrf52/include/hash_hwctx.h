#ifndef SHA256_HWCTX_H
#define SHA256_HWCTX_H

#include "cryptocell_incl/crys_hash.h"

typedef struct {
    CRYS_HASHUserContext_t cc310_ctx;
} hash_hwctx_t;

#endif /* SHA256_HWCTX_H */
