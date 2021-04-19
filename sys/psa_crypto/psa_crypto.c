#include <stdio.h>
#include "psa/crypto.h"
#include "psa/psa_crypto_driver_wrapper.h"

#include "kernel_defines.h"

static uint8_t lib_initialized = 0;

/* constant-time buffer comparison */
static inline int safer_memcmp(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;

    for (size_t i = 0; i < n; i++)
        diff |= a[i] ^ b[i];

    return diff;
}

psa_status_t psa_crypto_init(void)
{
    lib_initialized = 1;
    return PSA_SUCCESS;
}

psa_status_t psa_aead_abort(psa_aead_operation_t * operation)
{
    (void) operation;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_aead_decrypt(psa_key_id_t key,
                              psa_algorithm_t alg,
                              const uint8_t * nonce,
                              size_t nonce_length,
                              const uint8_t * additional_data,
                              size_t additional_data_length,
                              const uint8_t * ciphertext,
                              size_t ciphertext_length,
                              uint8_t * plaintext,
                              size_t plaintext_size,
                              size_t * plaintext_length)
{
    (void) key;
    (void) alg;
    (void) nonce;
    (void) nonce_length;
    (void) additional_data;
    (void) additional_data_length;
    (void) ciphertext;
    (void) ciphertext_length;
    (void) plaintext;
    (void) plaintext_size;
    (void) plaintext_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_aead_decrypt_setup(psa_aead_operation_t * operation,
                                    psa_key_id_t key,
                                    psa_algorithm_t alg)
{   
    (void) operation;
    (void) key;
    (void) alg;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_aead_encrypt(psa_key_id_t key,
                              psa_algorithm_t alg,
                              const uint8_t * nonce,
                              size_t nonce_length,
                              const uint8_t * additional_data,
                              size_t additional_data_length,
                              const uint8_t * plaintext,
                              size_t plaintext_length,
                              uint8_t * ciphertext,
                              size_t ciphertext_size,
                              size_t * ciphertext_length)
{
    (void) key;
    (void) alg;
    (void) nonce;
    (void) nonce_length;
    (void) additional_data;
    (void) additional_data_length;
    (void) plaintext;
    (void) plaintext_length;
    (void) ciphertext;
    (void) ciphertext_size;
    (void) ciphertext_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_aead_encrypt_setup(psa_aead_operation_t * operation,
                                    psa_key_id_t key,
                                    psa_algorithm_t alg)
{
    (void) operation;
    (void) key;
    (void) alg;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_aead_finish(psa_aead_operation_t * operation,
                             uint8_t * ciphertext,
                             size_t ciphertext_size,
                             size_t * ciphertext_length,
                             uint8_t * tag,
                             size_t tag_size,
                             size_t * tag_length)
{
    (void) operation;
    (void) ciphertext;
    (void) ciphertext_size;
    (void) ciphertext_length;
    (void) tag; 
    (void) tag_size;
    (void) tag_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_aead_generate_nonce(psa_aead_operation_t * operation,
                                     uint8_t * nonce,
                                     size_t nonce_size,
                                     size_t * nonce_length)
{
    (void) operation;
    (void) nonce;
    (void) nonce_size;
    (void) nonce_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_aead_operation_t psa_aead_operation_init(void)
{
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_aead_set_lengths(psa_aead_operation_t * operation,
                                  size_t ad_length,
                                  size_t plaintext_length)
{   (void) operation;
    (void) ad_length;
    (void) plaintext_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_aead_set_nonce(psa_aead_operation_t * operation,
                                const uint8_t * nonce,
                                size_t nonce_length)
{
    (void) operation;
    (void) nonce;
    (void) nonce_length;
    return PSA_ERROR_NOT_SUPPORTED;
}
                            
psa_status_t psa_aead_update(psa_aead_operation_t * operation,
                             const uint8_t * input,
                             size_t input_length,
                             uint8_t * output,
                             size_t output_size,
                             size_t * output_length)
{
    (void) operation;
    (void) input;
    (void) input_length;
    (void) output;
    (void) output_size;
    (void) output_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_aead_update_ad(psa_aead_operation_t * operation,
                                const uint8_t * input,
                                size_t input_length)
{
    (void) operation;
    (void) input;
    (void) input_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_aead_verify(psa_aead_operation_t * operation,
                             uint8_t * plaintext,
                             size_t plaintext_size,
                             size_t * plaintext_length,
                             const uint8_t * tag,
                             size_t tag_length)
{
    (void) operation;
    (void) plaintext;
    (void) plaintext_size;
    (void) plaintext_length;
    (void) tag;
    (void) tag_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_asymmetric_decrypt(psa_key_id_t key,
                                    psa_algorithm_t alg,
                                    const uint8_t * input,
                                    size_t input_length,
                                    const uint8_t * salt,
                                    size_t salt_length,
                                    uint8_t * output,
                                    size_t output_size,
                                    size_t * output_length)
{
    (void) key;
    (void) alg;
    (void) input;
    (void) input_length;
    (void) salt;
    (void) salt_length;
    (void) output;
    (void) output_size;
    (void) output_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_asymmetric_encrypt(psa_key_id_t key,
                                    psa_algorithm_t alg,
                                    const uint8_t * input,
                                    size_t input_length,
                                    const uint8_t * salt,
                                    size_t salt_length,
                                    uint8_t * output,
                                    size_t output_size,
                                    size_t * output_length)
{
    (void) key;
    (void) alg;
    (void) input;
    (void) input_length;
    (void) salt;
    (void) salt_length;
    (void) output;
    (void) output_size;
    (void) output_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_cipher_abort(psa_cipher_operation_t * operation)
{
    (void) operation;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_cipher_decrypt(psa_key_id_t key,
                                psa_algorithm_t alg,
                                const uint8_t * input,
                                size_t input_length,
                                uint8_t * output,
                                size_t output_size,
                                size_t * output_length)
{
    (void) key;
    (void) alg;
    (void) input;
    (void) input_length;
    (void) output;
    (void) output_size;
    (void) output_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_cipher_decrypt_setup(psa_cipher_operation_t * operation,
                                      psa_key_id_t key,
                                      psa_algorithm_t alg)
{
    (void) operation;
    (void) key;
    (void) alg;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_cipher_encrypt(psa_key_id_t key,
                                psa_algorithm_t alg,
                                const uint8_t * input,
                                size_t input_length,
                                uint8_t * output,
                                size_t output_size,
                                size_t * output_length)
{
    (void) key;
    (void) alg;
    (void) input;
    (void) input_length;
    (void) output;
    (void) output_size;
    (void) output_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_cipher_encrypt_setup(psa_cipher_operation_t * operation,
                                      psa_key_id_t key,
                                      psa_algorithm_t alg)
{
    (void) operation;
    (void) key;
    (void) alg;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_cipher_finish(psa_cipher_operation_t * operation,
                               uint8_t * output,
                               size_t output_size,
                               size_t * output_length)
{
    (void) operation;
    (void) output;
    (void) output_size;
    (void) output_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_cipher_generate_iv(psa_cipher_operation_t * operation,
                                    uint8_t * iv,
                                    size_t iv_size,
                                    size_t * iv_length)
{
    (void) operation;
    (void) iv;
    (void) iv_size;
    (void) iv_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_cipher_operation_t psa_cipher_operation_init(void)
{
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_cipher_set_iv(psa_cipher_operation_t * operation,
                               const uint8_t * iv,
                               size_t iv_length)
{
    (void) operation;
    (void) iv;
    (void) iv_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_cipher_update(psa_cipher_operation_t * operation,
                               const uint8_t * input,
                               size_t input_length,
                               uint8_t * output,
                               size_t output_size,
                               size_t * output_length)
{   (void) operation;
    (void) input;
    (void) input_length;
    (void) output;
    (void) output_size;
    (void) output_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_copy_key(psa_key_id_t source_key,
                          const psa_key_attributes_t * attributes,
                          psa_key_id_t * target_key)
{
    (void) source_key;
    (void) attributes;
    (void) target_key;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_destroy_key(psa_key_id_t key)
{
    (void) key;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_export_key(psa_key_id_t key,
                            uint8_t * data,
                            size_t data_size,
                            size_t * data_length)
{
    (void) key;
    (void) data;
    (void) data_size;
    (void) data_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_export_public_key(psa_key_id_t key,
                                   uint8_t * data,
                                   size_t data_size,
                                   size_t * data_length)
{
    (void) key;
    (void) data;
    (void) data_size;
    (void) data_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_generate_key(const psa_key_attributes_t * attributes,
                              psa_key_id_t * key)
{
    (void) attributes;
    (void) key;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_generate_random(uint8_t * output,
                                 size_t output_size)
{
    (void) output;
    (void) output_size;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_algorithm_t psa_get_key_algorithm(const psa_key_attributes_t * attributes)
{
    (void) attributes;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_get_key_attributes(psa_key_id_t key,
                                    psa_key_attributes_t * attributes)
{
    (void) key;
    (void) attributes;
    return PSA_ERROR_NOT_SUPPORTED;
}

size_t psa_get_key_bits(const psa_key_attributes_t * attributes)
{
    (void) attributes;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_key_id_t psa_get_key_id(const psa_key_attributes_t * attributes)
{
    (void) attributes;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_key_lifetime_t psa_get_key_lifetime(const psa_key_attributes_t * attributes)
{
    (void) attributes;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_key_type_t psa_get_key_type(const psa_key_attributes_t * attributes)
{
    (void) attributes;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_key_usage_t psa_get_key_usage_flags(const psa_key_attributes_t * attributes)
{
    (void) attributes;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_hash_setup(psa_hash_operation_t * operation,
                            psa_algorithm_t alg)
{
    if ((lib_initialized == 0) || (operation->alg != 0)) {
        return PSA_ERROR_BAD_STATE;
    }

    if (!PSA_ALG_IS_HASH(alg)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

#if IS_ACTIVE(CONFIG_HW_HASHES_ENABLED)
    psa_status_t status = psa_driver_wrapper_hash_setup(operation, alg);

    if (status == PSA_ERROR_NOT_SUPPORTED) {
#endif
        switch(alg) {
        #if IS_ACTIVE(CONFIG_SW_HASH_MD5)
            case PSA_ALG_MD5:
                md5_init(&(operation->sw_ctx.md5));
                break;
        #endif
        #if IS_ACTIVE(CONFIG_SW_HASH_SHA1)
            case PSA_ALG_SHA_1:
                sha1_init(&(operation->sw_ctx.sha1));
                break;
        #endif
        #if IS_ACTIVE(CONFIG_SW_HASH_SHA224)
            case PSA_ALG_SHA_224:
                sha224_init(&(operation->sw_ctx.sha224));
                break;
        #endif
        #if IS_ACTIVE(CONFIG_SW_HASH_SHA256)
            case PSA_ALG_SHA_256:
                sha256_init(&(operation->sw_ctx.sha256));
                break;
        #endif  
            default:
                return PSA_ERROR_NOT_SUPPORTED;
        }

#if IS_ACTIVE(CONFIG_HW_HASHES_ENABLED)
    }

    if (status != PSA_SUCCESS && status != PSA_ERROR_NOT_SUPPORTED) {
        return status;
    }
#endif

    operation->alg = alg;
    operation->suspended = 0;

    return PSA_SUCCESS;
}

psa_status_t psa_hash_update(psa_hash_operation_t * operation,
                             const uint8_t * input,
                             size_t input_length)
{
    if ((lib_initialized == 0) || 
        (operation->alg == 0) || 
        (operation->suspended == 1)) {
        return PSA_ERROR_BAD_STATE;
    }

#if IS_ACTIVE(CONFIG_HW_HASHES_ENABLED)
    psa_status_t status = psa_driver_wrapper_hash_update(operation, input, input_length);

    if (status == PSA_ERROR_NOT_SUPPORTED) {
#endif

        switch(operation->alg) {
        #if IS_ACTIVE(CONFIG_SW_HASH_MD5)
            case PSA_ALG_MD5:
                md5_update(&(operation->sw_ctx.md5), input, input_length);
                break;
        #endif
        #if IS_ACTIVE(CONFIG_SW_HASH_SHA1)
            case PSA_ALG_SHA_1:
                sha1_update(&(operation->sw_ctx.sha1), input, input_length);
                break;
        #endif
        #if IS_ACTIVE(CONFIG_SW_HASH_SHA224)
            case PSA_ALG_SHA_224:
                sha224_update(&(operation->sw_ctx.sha224), input, input_length);
                break;
        #endif
        #if IS_ACTIVE(CONFIG_SW_HASH_SHA256)
            case PSA_ALG_SHA_256:
                sha256_update(&(operation->sw_ctx.sha256), input, input_length);
                break;
        #endif  
            default:
                (void) input;
                (void) input_length;
                return PSA_ERROR_NOT_SUPPORTED;
        }

#if IS_ACTIVE(CONFIG_HW_HASHES_ENABLED)
    }

    if (status != PSA_SUCCESS && status != PSA_ERROR_NOT_SUPPORTED) {
        psa_hash_abort(operation);
        return status;
    }
#endif

    return PSA_SUCCESS;
}

psa_status_t psa_hash_finish(psa_hash_operation_t * operation,
                             uint8_t * hash,
                             size_t hash_size,
                             size_t * hash_length)
{
    if ((lib_initialized == 0) || 
        (operation->alg == 0) || 
        (operation->suspended == 1)) {
        return PSA_ERROR_BAD_STATE;
    }
    uint8_t actual_hash_length = PSA_HASH_LENGTH(operation->alg);
    
    if (hash_size < actual_hash_length) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }

#if IS_ACTIVE(CONFIG_HW_HASHES_ENABLED)
    psa_status_t status = psa_driver_wrapper_hash_finish(operation, hash);

    if (status == PSA_ERROR_NOT_SUPPORTED) {
#endif

        switch(operation->alg) {
        #if IS_ACTIVE(CONFIG_SW_HASH_MD5)
            case PSA_ALG_MD5:
                md5_final(&(operation->sw_ctx.md5), hash);
                break;
        #endif
        #if IS_ACTIVE(CONFIG_SW_HASH_SHA1)
            case PSA_ALG_SHA_1:
                sha1_final(&(operation->sw_ctx.sha1), hash);
                break;
        #endif
        #if IS_ACTIVE(CONFIG_SW_HASH_SHA224)
            case PSA_ALG_SHA_224:
                sha224_final(&(operation->sw_ctx.sha224), hash);
                break;
        #endif
        #if IS_ACTIVE(CONFIG_SW_HASH_SHA256)
            case PSA_ALG_SHA_256:
                sha256_final(&(operation->sw_ctx.sha256), hash);
                break;
        #endif  
            default:
                (void) hash;
                return PSA_ERROR_NOT_SUPPORTED;
        }

#if IS_ACTIVE(CONFIG_HW_HASHES_ENABLED)
    }

    if (status != PSA_SUCCESS && status != PSA_ERROR_NOT_SUPPORTED) {
        psa_hash_abort(operation);
        return status;
    }
#endif

    *hash_length = actual_hash_length;

    /* Make sure operation becomes inactive after successfull execution */
    psa_hash_abort(operation);

    return PSA_SUCCESS;
}

psa_status_t psa_hash_verify(psa_hash_operation_t * operation,
                             const uint8_t * hash,
                             size_t hash_length)
{
    if ((lib_initialized == 0) || 
        (operation->alg == 0) || 
        (operation->suspended == 1)) {
        return PSA_ERROR_BAD_STATE;
    }

    int status = PSA_ERROR_CORRUPTION_DETECTED;

    uint8_t digest_length = PSA_HASH_LENGTH(operation->alg);
    uint8_t digest[digest_length];
    size_t actual_hash_length = 0;

    status = psa_hash_finish(operation, digest, digest_length, &actual_hash_length);

    if (status != PSA_SUCCESS) {
        return status;
    }
    if (actual_hash_length != hash_length) { 
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    if (safer_memcmp(hash, digest, hash_length) != 0) {
        return PSA_ERROR_INVALID_SIGNATURE;
    }

    return PSA_SUCCESS;
}

psa_status_t psa_hash_suspend(psa_hash_operation_t * operation,
                              uint8_t * hash_state,
                              size_t hash_state_size,
                              size_t * hash_state_length)
{
    (void) operation;
    (void) hash_state;
    (void) hash_state_size;
    (void) hash_state_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_hash_resume(psa_hash_operation_t * operation,
                             const uint8_t * hash_state,
                             size_t hash_state_length)
{
    (void) operation;
    (void) hash_state;
    (void) hash_state_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_hash_abort(psa_hash_operation_t * operation)
{
    *operation = psa_hash_operation_init();
    return PSA_SUCCESS;
}

psa_status_t psa_hash_clone(const psa_hash_operation_t * source_operation,
                            psa_hash_operation_t * target_operation)
{
    (void) source_operation;
    (void) target_operation;
    return PSA_ERROR_NOT_SUPPORTED;
}
                        
psa_status_t psa_hash_compare(psa_algorithm_t alg,
                              const uint8_t * input,
                              size_t input_length,
                              const uint8_t * hash,
                              size_t hash_length)
{
    psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    status = psa_hash_setup(&operation, alg);
    if (status != PSA_SUCCESS) {
        return status;
    }
    status = psa_hash_update(&operation, input, input_length);
    if (status != PSA_SUCCESS) {
        return status;
    }
    status = psa_hash_verify(&operation, hash, hash_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    return PSA_SUCCESS;
}

psa_status_t psa_hash_compute(psa_algorithm_t alg,
                              const uint8_t * input,
                              size_t input_length,
                              uint8_t * hash,
                              size_t hash_size,
                              size_t * hash_length)
{
    psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;

    *hash_length = hash_size;
    status = psa_hash_setup(&operation, alg);
    if (status != PSA_SUCCESS) {
        return status;
    }
    status = psa_hash_update(&operation, input, input_length);
    if (status != PSA_SUCCESS) {
        return status;
    }
    status = psa_hash_finish(&operation, hash, hash_size, hash_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    return PSA_SUCCESS;
}

psa_status_t psa_import_key(const psa_key_attributes_t * attributes,
                            const uint8_t * data,
                            size_t data_length,
                            psa_key_id_t * key)
{
    (void) attributes;
    (void) data;
    (void) data_length;
    (void) key;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_key_derivation_abort(psa_key_derivation_operation_t * operation)
{
    (void) operation;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_key_derivation_get_capacity(const psa_key_derivation_operation_t * operation,
                                             size_t * capacity)
{
    (void) operation;
    (void) capacity;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_key_derivation_input_bytes(psa_key_derivation_operation_t * operation,
                                            psa_key_derivation_step_t step,
                                            const uint8_t * data,
                                            size_t data_length)
{
    (void) operation;
    (void) step;
    (void) data;
    (void) data_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_key_derivation_input_key(psa_key_derivation_operation_t * operation,
                                          psa_key_derivation_step_t step,
                                          psa_key_id_t key)
{
    (void) operation;
    (void) step;
    (void) key;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_key_derivation_key_agreement(psa_key_derivation_operation_t * operation,
                                              psa_key_derivation_step_t step,
                                              psa_key_id_t private_key,
                                              const uint8_t * peer_key,
                                              size_t peer_key_length)
{
    (void) operation;
    (void) step;
    (void) private_key;
    (void) peer_key;
    (void) peer_key_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_key_derivation_operation_t psa_key_derivation_operation_init(void)
{
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_key_derivation_output_bytes(psa_key_derivation_operation_t * operation,
                                             uint8_t * output,
                                             size_t output_length)
{
    (void) operation;
    (void) output;
    (void) output_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_key_derivation_output_key(const psa_key_attributes_t * attributes,
                                           psa_key_derivation_operation_t * operation,
                                           psa_key_id_t * key)
{
    (void) attributes;
    (void) operation;
    (void) key;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_key_derivation_set_capacity(psa_key_derivation_operation_t * operation,
                                             size_t capacity)
{
    (void) operation;
    (void) capacity;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_key_derivation_setup(psa_key_derivation_operation_t * operation,
                                      psa_algorithm_t alg)
{
    (void) operation;
    (void) alg;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_mac_abort(psa_mac_operation_t * operation)
{
    (void) operation;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_mac_compute(psa_key_id_t key,
                             psa_algorithm_t alg,
                             const uint8_t * input,
                             size_t input_length,
                             uint8_t * mac,
                             size_t mac_size,
                             size_t * mac_length)
{
    (void) key;
    (void) alg;
    (void) input;
    (void) input_length;
    (void) mac;
    (void) mac_size;
    (void) mac_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_mac_operation_t psa_mac_operation_init(void)
{
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_mac_sign_finish(psa_mac_operation_t * operation,
                                 uint8_t * mac,
                                 size_t mac_size,
                                 size_t * mac_length)
{
    (void) operation;
    (void) mac;
    (void) mac_size;
    (void) mac_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_mac_sign_setup(psa_mac_operation_t * operation,
                                psa_key_id_t key,
                                psa_algorithm_t alg)
{
    (void) operation;
    (void) key;
    (void) alg;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_mac_update(psa_mac_operation_t * operation,
                            const uint8_t * input,
                            size_t input_length)
{
    (void) operation;
    (void) input;
    (void) input_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_mac_verify(psa_key_id_t key,
                            psa_algorithm_t alg,
                            const uint8_t * input,
                            size_t input_length,
                            const uint8_t * mac,
                            size_t mac_length)
{
    (void) key;
    (void) alg;
    (void) input;
    (void) input_length;
    (void) mac;
    (void) mac_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_mac_verify_finish(psa_mac_operation_t * operation,
                                   const uint8_t * mac,
                                   size_t mac_length)
{
    (void) operation;
    (void) mac;
    (void) mac_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_mac_verify_setup(psa_mac_operation_t * operation,
                                  psa_key_id_t key,
                                  psa_algorithm_t alg)
{
    (void) operation;
    (void) key;
    (void) alg;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_purge_key(psa_key_id_t key)
{
    (void) key;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_raw_key_agreement(psa_algorithm_t alg,
                                   psa_key_id_t private_key,
                                   const uint8_t * peer_key,
                                   size_t peer_key_length,
                                   uint8_t * output,
                                   size_t output_size,
                                   size_t * output_length)
{
    (void) alg;
    (void) private_key;
    (void) peer_key;
    (void) peer_key_length;
    (void) output;
    (void) output_size;
    (void) output_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

void psa_reset_key_attributes(psa_key_attributes_t * attributes)
{
    (void) attributes;
}

void psa_set_key_algorithm(psa_key_attributes_t * attributes,
                           psa_algorithm_t alg)
{
    (void) attributes;
    (void) alg;
}

void psa_set_key_bits(psa_key_attributes_t * attributes,
                      size_t bits)
{
    (void) attributes;
    (void) bits;
}

void psa_set_key_id(psa_key_attributes_t * attributes,
                    psa_key_id_t id)
{
    (void) attributes;
    (void) id;
}

void psa_set_key_lifetime(psa_key_attributes_t * attributes,
                          psa_key_lifetime_t lifetime)
{
    (void) attributes;
    (void) lifetime;
}

void psa_set_key_type(psa_key_attributes_t * attributes,
                      psa_key_type_t type)
{
    (void) attributes;
    (void) type;
}

void psa_set_key_usage_flags(psa_key_attributes_t * attributes,
                             psa_key_usage_t usage_flags)
{
    (void) attributes;
    (void) usage_flags;
}

psa_status_t psa_sign_hash(psa_key_id_t key,
                           psa_algorithm_t alg,
                           const uint8_t * hash,
                           size_t hash_length,
                           uint8_t * signature,
                           size_t signature_size,
                           size_t * signature_length)
{
    (void) key;
    (void) alg;
    (void) hash;
    (void) hash_length;
    (void) signature;
    (void) signature_size;
    (void) signature_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_sign_message(psa_key_id_t key,
                              psa_algorithm_t alg,
                              const uint8_t * input,
                              size_t input_length,
                              uint8_t * signature,
                              size_t signature_size,
                              size_t * signature_length)
{
    (void) key;
    (void) alg;
    (void) input;
    (void) input_length;
    (void) signature;
    (void) signature_size;
    (void) signature_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_verify_hash(psa_key_id_t key,
                             psa_algorithm_t alg,
                             const uint8_t * hash,
                             size_t hash_length,
                             const uint8_t * signature,
                             size_t signature_length)
{
    (void) key;
    (void) alg;
    (void) hash;
    (void) hash_length;
    (void) signature;
    (void) signature_length;
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_verify_message(psa_key_id_t key,
                                psa_algorithm_t alg,
                                const uint8_t * input,
                                size_t input_length,
                                const uint8_t * signature,
                                size_t signature_length)
{
    (void) key;
    (void) alg;
    (void) input;
    (void) input_length;
    (void) signature;
    (void) signature_length;
    return PSA_ERROR_NOT_SUPPORTED;
}
