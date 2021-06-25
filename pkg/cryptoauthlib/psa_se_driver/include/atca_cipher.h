#ifndef ATCA_CIPHER_H
#define ATCA_CIPHER_H

#include "psa/crypto_se_driver.h"

const psa_drv_se_cipher_t atca_cipher = {
    0,
    atca_cipher_setup,
    atca_cipher_set_iv,
    atca_cipher_update,
    atca_cipher_finish,
    atca_cipher_abort,
    atca_cipher_ecb
};

psa_status_t atca_cipher_setup( psa_drv_se_context_t *drv_context,
                                void *op_context,
                                psa_key_slot_number_t key_slot,
                                psa_algorithm_t algorithm,
                                psa_encrypt_or_decrypt_t direction);

psa_status_t atca_cipher_set_iv(void *op_context,
                                const uint8_t *p_iv,
                                size_t iv_length);

psa_status_t atca_cipher_update(void *op_context,
                                const uint8_t *p_input,
                                size_t input_size,
                                uint8_t *p_output,
                                size_t output_size,
                                size_t *p_output_length);

psa_status_t atca_cipher_finish(void *op_context,
                                uint8_t *p_output,
                                size_t output_size,
                                size_t *p_output_length);

psa_status_t atca_cipher_abort(void *op_context);

psa_status_t atca_cipher_ecb(   psa_drv_se_context_t *drv_context,
                                psa_key_slot_number_t key_slot,
                                psa_algorithm_t algorithm,
                                psa_encrypt_or_decrypt_t direction,
                                const uint8_t *p_input,
                                size_t input_size,
                                uint8_t *p_output,
                                size_t output_size);

#endif /* ATCA_CIPHER_H */
