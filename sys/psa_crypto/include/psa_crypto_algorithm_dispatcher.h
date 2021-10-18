#ifndef PSA_CRYPTO_ALGORITHM_DISPATCHER_H
#define PSA_CRYPTO_ALGORITHM_DISPATCHER_H

#include "psa/crypto.h"
#include "psa_crypto_slot_management.h"

psa_status_t psa_cipher_dispatch_encrypt(   psa_key_slot_t *slot,
                                            psa_algorithm_t alg,
                                            const uint8_t * input,
                                            size_t input_length,
                                            uint8_t * output,
                                            size_t output_size,
                                            size_t * output_length);

#endif /* PSA_CRYPTO_ALGORITHM_DISPATCHER_H */