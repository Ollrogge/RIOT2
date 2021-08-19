#include "psa/crypto.h"
#include "hashes/psa/riot_hashes.h"

psa_status_t psa_hashes_sha256_setup(psa_hashes_sha256_ctx_t * ctx)
{
    sha256_init((sha256_context_t *) ctx);
    return PSA_SUCCESS;
}

psa_status_t psa_hashes_sha256_update(psa_hashes_sha256_ctx_t * ctx,
                             const uint8_t * input,
                             size_t input_length)
{
    sha256_update((sha256_context_t *) ctx, input, input_length);
    return PSA_SUCCESS;
}

psa_status_t psa_hashes_sha256_finish(psa_hashes_sha256_ctx_t * ctx,
                             uint8_t * hash,
                             size_t hash_size,
                             size_t * hash_length)
{
    sha256_final((sha256_context_t *) ctx, hash);

    (void) hash_size;
    (void) hash_length;
    return PSA_SUCCESS;
}
