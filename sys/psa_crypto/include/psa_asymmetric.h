#include "psa/crypto.h"

psa_status_t psa_generate_ecc_secp_r1_256_key_pair( const psa_key_attributes_t *attributes,
                                                    uint8_t *key_buffer, size_t key_buffer_size,
                                                    size_t *key_buffer_length);