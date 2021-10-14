#ifndef PSA_BUILTIN_KEY_MANAGEMENT_H
#define PSA_BUILTIN_KEY_MANAGEMENT_H

#include "psa/crypto.h"

psa_status_t psa_builtin_import_key(const psa_key_attributes_t *attributes,
                                    const uint8_t *data, size_t data_length,
                                    uint8_t *key_buffer, size_t key_buffer_size,
                                    size_t *key_buffer_length, size_t *bits);

psa_status_t psa_builtin_generate_key(  const psa_key_attributes_t *attributes,
                                        uint8_t *key_buffer, size_t key_buffer_size,
                                        size_t *key_buffer_length);

#endif /* PSA_BUILTIN_KEY_MANAGEMENT_H */
