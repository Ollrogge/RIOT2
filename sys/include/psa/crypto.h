/*
 * Copyright (C) 2021 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     sys_psa_crypto
 * @{
 *
 * @file
 * @brief       Function declarations for PSA Crypto API
 *
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 * @}
 */

#ifndef PSA_CRYPTO_H
#define PSA_CRYPTO_H

#include <stdlib.h>
#include "crypto_sizes.h"
#include "crypto_struct.h"
#include "crypto_values.h"
#include "crypto_types.h"

/**
 * The major version of this implementation of the PSA Crypto API
 */
#define PSA_CRYPTO_API_VERSION_MAJOR 1

/**
 * The minor version of this implementation of the PSA Crypto API
 */
#define PSA_CRYPTO_API_VERSION_MINOR 0

/**
 * Library initialization.
 */
psa_status_t psa_crypto_init(void);

psa_status_t psa_aead_abort(psa_aead_operation_t * operation);
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
                              size_t * plaintext_length);
psa_status_t psa_aead_decrypt_setup(psa_aead_operation_t * operation,
                                    psa_key_id_t key,
                                    psa_algorithm_t alg);
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
                              size_t * ciphertext_length);
psa_status_t psa_aead_encrypt_setup(psa_aead_operation_t * operation,
                                    psa_key_id_t key,
                                    psa_algorithm_t alg);
psa_status_t psa_aead_finish(psa_aead_operation_t * operation,
                             uint8_t * ciphertext,
                             size_t ciphertext_size,
                             size_t * ciphertext_length,
                             uint8_t * tag,
                             size_t tag_size,
                             size_t * tag_length);
psa_status_t psa_aead_generate_nonce(psa_aead_operation_t * operation,
                                     uint8_t * nonce,
                                     size_t nonce_size,
                                     size_t * nonce_length);
psa_aead_operation_t psa_aead_operation_init(void);
psa_status_t psa_aead_set_lengths(psa_aead_operation_t * operation,
                                  size_t ad_length,
                                  size_t plaintext_length);
psa_status_t psa_aead_set_nonce(psa_aead_operation_t * operation,
                                const uint8_t * nonce,
                                size_t nonce_length);
psa_status_t psa_aead_update(psa_aead_operation_t * operation,
                             const uint8_t * input,
                             size_t input_length,
                             uint8_t * output,
                             size_t output_size,
                             size_t * output_length);
psa_status_t psa_aead_update_ad(psa_aead_operation_t * operation,
                                const uint8_t * input,
                                size_t input_length);
psa_status_t psa_aead_verify(psa_aead_operation_t * operation,
                             uint8_t * plaintext,
                             size_t plaintext_size,
                             size_t * plaintext_length,
                             const uint8_t * tag,
                             size_t tag_length);
psa_status_t psa_asymmetric_decrypt(psa_key_id_t key,
                                    psa_algorithm_t alg,
                                    const uint8_t * input,
                                    size_t input_length,
                                    const uint8_t * salt,
                                    size_t salt_length,
                                    uint8_t * output,
                                    size_t output_size,
                                    size_t * output_length);
psa_status_t psa_asymmetric_encrypt(psa_key_id_t key,
                                    psa_algorithm_t alg,
                                    const uint8_t * input,
                                    size_t input_length,
                                    const uint8_t * salt,
                                    size_t salt_length,
                                    uint8_t * output,
                                    size_t output_size,
                                    size_t * output_length);
psa_status_t psa_cipher_abort(psa_cipher_operation_t * operation);
psa_status_t psa_cipher_decrypt(psa_key_id_t key,
                                psa_algorithm_t alg,
                                const uint8_t * input,
                                size_t input_length,
                                uint8_t * output,
                                size_t output_size,
                                size_t * output_length);
psa_status_t psa_cipher_decrypt_setup(psa_cipher_operation_t * operation,
                                      psa_key_id_t key,
                                      psa_algorithm_t alg);
psa_status_t psa_cipher_encrypt(psa_key_id_t key,
                                psa_algorithm_t alg,
                                const uint8_t * input,
                                size_t input_length,
                                uint8_t * output,
                                size_t output_size,
                                size_t * output_length);
psa_status_t psa_cipher_encrypt_setup(psa_cipher_operation_t * operation,
                                      psa_key_id_t key,
                                      psa_algorithm_t alg);
psa_status_t psa_cipher_finish(psa_cipher_operation_t * operation,
                               uint8_t * output,
                               size_t output_size,
                               size_t * output_length);
psa_status_t psa_cipher_generate_iv(psa_cipher_operation_t * operation,
                                    uint8_t * iv,
                                    size_t iv_size,
                                    size_t * iv_length);
psa_cipher_operation_t psa_cipher_operation_init(void);
psa_status_t psa_cipher_set_iv(psa_cipher_operation_t * operation,
                               const uint8_t * iv,
                               size_t iv_length);
psa_status_t psa_cipher_update(psa_cipher_operation_t * operation,
                               const uint8_t * input,
                               size_t input_length,
                               uint8_t * output,
                               size_t output_size,
                               size_t * output_length);
psa_status_t psa_copy_key(psa_key_id_t source_key,
                          const psa_key_attributes_t * attributes,
                          psa_key_id_t * target_key);
psa_status_t psa_crypto_init(void);
psa_status_t psa_destroy_key(psa_key_id_t key);
psa_status_t psa_export_key(psa_key_id_t key,
                            uint8_t * data,
                            size_t data_size,
                            size_t * data_length);
psa_status_t psa_export_public_key(psa_key_id_t key,
                                   uint8_t * data,
                                   size_t data_size,
                                   size_t * data_length);
psa_status_t psa_generate_key(const psa_key_attributes_t * attributes,
                              psa_key_id_t * key);
psa_status_t psa_generate_random(uint8_t * output,
                                 size_t output_size);
psa_algorithm_t psa_get_key_algorithm(const psa_key_attributes_t * attributes);
psa_status_t psa_get_key_attributes(psa_key_id_t key,
                                    psa_key_attributes_t * attributes);
size_t psa_get_key_bits(const psa_key_attributes_t * attributes);
psa_key_id_t psa_get_key_id(const psa_key_attributes_t * attributes);
psa_key_lifetime_t psa_get_key_lifetime(const psa_key_attributes_t * attributes);
psa_key_type_t psa_get_key_type(const psa_key_attributes_t * attributes);
psa_key_usage_t psa_get_key_usage_flags(const psa_key_attributes_t * attributes);

/** @brief Abort a hash operation.
 *
 * Aborting an operation frees all associated resources except for the
 * \p operation structure itself. Once aborted, the operation object
 * can be reused for another operation by calling
 * psa_hash_setup() again.
 *
 * You may call this function any time after the operation object has
 * been initialized by one of the methods described in #psa_hash_operation_t.
 *
 * In particular, calling psa_hash_abort() after the operation has been
 * terminated by a call to psa_hash_abort(), psa_hash_finish() or
 * psa_hash_verify() is safe and has no effect.
 *
 * @param[in,out] operation     Initialized hash operation.
 *
 * @return PSA_SUCCESS
 * @return PSA_ERROR_COMMUNICATION_FAILURE
 * @return PSA_ERROR_HARDWARE_FAILURE
 * @return PSA_ERROR_CORRUPTION_DETECTED
 * @return PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_hash_abort(psa_hash_operation_t * operation);

/** @brief Clone a hash operation.
 *
 * This function copies the state of an ongoing hash operation to
 * a new operation object. In other words, this function is equivalent
 * to calling psa_hash_setup() on \p target_operation with the same
 * algorithm that \p source_operation was set up for, then
 * psa_hash_update() on \p target_operation with the same input that
 * that was passed to \p source_operation. After this function returns, the
 * two objects are independent, i.e. subsequent calls involving one of
 * the objects do not affect the other object.
 *
 * @param[in] source_operation      The active hash operation to clone.
 * @param[in,out] target_operation  The operation object to set up.
 *                                  It must be initialized but not active.
 *
 * @return PSA_SUCCESS
 * @return PSA_ERROR_BAD_STATE
 *         The \p source_operation state is not valid (it must be active).
 * @return PSA_ERROR_BAD_STATE
 *         The \p target_operation state is not valid (it must be inactive).
 * @return PSA_ERROR_COMMUNICATION_FAILURE
 * @return PSA_ERROR_HARDWARE_FAILURE
 * @return PSA_ERROR_CORRUPTION_DETECTED
 * @return PSA_ERROR_INSUFFICIENT_MEMORY
 * @return PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_hash_clone(const psa_hash_operation_t * source_operation,
                            psa_hash_operation_t * target_operation);

/** @brief Calculate the hash (digest) of a message and compare it with a
 * reference value.
 *
 * @param alg               The hash algorithm to compute (\c PSA_ALG_XXX value
 *                          such that #PSA_ALG_IS_HASH(\p alg) is true).
 * @param[in] input         Buffer containing the message to hash.
 * @param input_length      Size of the \p input buffer in bytes.
 * @param[out] hash         Buffer containing the expected hash value.
 * @param hash_length       Size of the \p hash buffer in bytes.
 *
 * @return PSA_SUCCESS
 *         The expected hash is identical to the actual hash of the input.
 * @return PSA_ERROR_INVALID_SIGNATURE
 *         The hash of the message was calculated successfully, but it
 *         differs from the expected hash.
 * @return PSA_ERROR_NOT_SUPPORTED
 *         \p alg is not supported or is not a hash algorithm.
 * @return PSA_ERROR_INVALID_ARGUMENT
 *         \p input_length or \p hash_length do not match the hash size for \p alg
 * @return PSA_ERROR_INSUFFICIENT_MEMORY
 * @return PSA_ERROR_COMMUNICATION_FAILURE
 * @return PSA_ERROR_HARDWARE_FAILURE
 * @return PSA_ERROR_CORRUPTION_DETECTED
 * @return PSA_ERROR_INSUFFICIENT_MEMORY
 * @return PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_hash_compare(psa_algorithm_t alg,
                              const uint8_t * input,
                              size_t input_length,
                              const uint8_t * hash,
                              size_t hash_length);

/** @brief Calculate the hash (digest) of a message.
 *
 * @note To verify the hash of a message against an
 *       expected value, use psa_hash_compare() instead.
 *
 * @param alg               The hash algorithm to compute (\c PSA_ALG_XXX value
 *                          such that #PSA_ALG_IS_HASH(\p alg) is true).
 * @param[in] input         Buffer containing the message to hash.
 * @param input_length      Size of the \p input buffer in bytes.
 * @param[out] hash         Buffer where the hash is to be written.
 * @param hash_size         Size of the \p hash buffer in bytes.
 * @param[out] hash_length  On success, the number of bytes
 *                          that make up the hash value. This is always
 *                          #PSA_HASH_LENGTH(\p alg).
 *
 * @return PSA_SUCCESS
 *         Success.
 * @return PSA_ERROR_NOT_SUPPORTED
 *         \p alg is not supported or is not a hash algorithm.
 * @return PSA_ERROR_INVALID_ARGUMENT
 * @return PSA_ERROR_BUFFER_TOO_SMALL
 *         \p hash_size is too small
 * @return PSA_ERROR_INSUFFICIENT_MEMORY
 * @return PSA_ERROR_COMMUNICATION_FAILURE
 * @return PSA_ERROR_HARDWARE_FAILURE
 * @return PSA_ERROR_CORRUPTION_DETECTED
 * @return PSA_ERROR_INSUFFICIENT_MEMORY
 * @return PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_hash_compute(psa_algorithm_t alg,
                              const uint8_t * input,
                              size_t input_length,
                              uint8_t * hash,
                              size_t hash_size,
                              size_t * hash_length);

/** @brief Finish the calculation of the hash of a message.
 *
 * The application must call psa_hash_setup() before calling this function.
 * This function calculates the hash of the message formed by concatenating
 * the inputs passed to preceding calls to psa_hash_update().
 *
 * When this function returns successfuly, the operation becomes inactive.
 * If this function returns an error status, the operation enters an error
 * state and must be aborted by calling psa_hash_abort().
 *
 * @warning Applications should not call this function if they expect
 *          a specific value for the hash. Call psa_hash_verify() instead.
 *          Beware that comparing integrity or authenticity data such as
 *          hash values with a function such as \c memcmp is risky
 *          because the time taken by the comparison may leak information
 *          about the hashed data which could allow an attacker to guess
 *          a valid hash and thereby bypass security controls.
 *
 * @param[in,out] operation     Active hash operation.
 * @param[out] hash             Buffer where the hash is to be written.
 * @param hash_size             Size of the \p hash buffer in bytes.
 * @param[out] hash_length      On success, the number of bytes
 *                              that make up the hash value. This is always
 *                              #PSA_HASH_LENGTH(\c alg) where \c alg is the
 *                              hash algorithm that is calculated.
 *
 * @return PSA_SUCCESS
 *         Success.
 * @return PSA_ERROR_BAD_STATE
 *         The operation state is not valid (it must be active).
 * @return PSA_ERROR_BUFFER_TOO_SMALL
 *         The size of the \p hash buffer is too small. You can determine a
 *         sufficient buffer size by calling #PSA_HASH_LENGTH(\c alg)
 *         where \c alg is the hash algorithm that is calculated.
 * @return PSA_ERROR_INSUFFICIENT_MEMORY
 * @return PSA_ERROR_COMMUNICATION_FAILURE
 * @return PSA_ERROR_HARDWARE_FAILURE
 * @return PSA_ERROR_CORRUPTION_DETECTED
 * @return PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_hash_finish(psa_hash_operation_t * operation,
                             uint8_t * hash,
                             size_t hash_size,
                             size_t * hash_length);

/** Return an initial value for a hash operation object.
 */
psa_hash_operation_t psa_hash_operation_init(void);
psa_status_t psa_hash_resume(psa_hash_operation_t * operation,
                             const uint8_t * hash_state,
                             size_t hash_state_length);

/** @brief Set up a multipart hash operation.
 *
 * The sequence of operations to calculate a hash (message digest)
 * is as follows:
 * -# Allocate an operation object which will be passed to all the functions
 *    listed here.
 * -# Initialize the operation object with one of the methods described in the
 *    documentation for #psa_hash_operation_t, e.g. #PSA_HASH_OPERATION_INIT.
 * -# Call psa_hash_setup() to specify the algorithm.
 * -# Call psa_hash_update() zero, one or more times, passing a fragment
 *    of the message each time. The hash that is calculated is the hash
 *    of the concatenation of these messages in order.
 * -# To calculate the hash, call psa_hash_finish().
 *    To compare the hash with an expected value, call psa_hash_verify().
 *
 * If an error occurs at any step after a call to psa_hash_setup(), the
 * operation will need to be reset by a call to psa_hash_abort(). The
 * application may call psa_hash_abort() at any time after the operation
 * has been initialized.
 *
 * After a successful call to psa_hash_setup(), the application must
 * eventually terminate the operation. The following events terminate an
 * operation:
 * - A successful call to psa_hash_finish() or psa_hash_verify().
 * - A call to psa_hash_abort().
 *
 * @param[in,out] operation The operation object to set up. It must have
 *                          been initialized as per the documentation for
 *                          #psa_hash_operation_t and not yet in use.
 * @param alg               The hash algorithm to compute (\c PSA_ALG_XXX value
 *                          such that #PSA_ALG_IS_HASH(\p alg) is true).
 *
 * @return PSA_SUCCESS
 *         Success.
 * @return PSA_ERROR_NOT_SUPPORTED
 *         \p alg is not a supported hash algorithm.
 * @return PSA_ERROR_INVALID_ARGUMENT
 *         \p alg is not a hash algorithm.
 * @return PSA_ERROR_BAD_STATE
 *         The operation state is not valid (it must be inactive).
 * @return PSA_ERROR_INSUFFICIENT_MEMORY
 * @return PSA_ERROR_COMMUNICATION_FAILURE
 * @return PSA_ERROR_HARDWARE_FAILURE
 * @return PSA_ERROR_CORRUPTION_DETECTED
 * @return PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_hash_setup(psa_hash_operation_t * operation,
                            psa_algorithm_t alg);
psa_status_t psa_hash_suspend(psa_hash_operation_t * operation,
                              uint8_t * hash_state,
                              size_t hash_state_size,
                              size_t * hash_state_length);

/** @brief Add a message fragment to a multipart hash operation.
 *
 * The application must call psa_hash_setup() before calling this function.
 *
 * If this function returns an error status, the operation enters an error
 * state and must be aborted by calling psa_hash_abort().
 *
 * @param[in,out] operation Active hash operation.
 * @param[in] input         Buffer containing the message fragment to hash.
 * @param input_length      Size of the \p input buffer in bytes.
 *
 * @return PSA_SUCCESS
 *         Success.
 * @return PSA_ERROR_BAD_STATE
 *         The operation state is not valid (it muct be active).
 * @return PSA_ERROR_INSUFFICIENT_MEMORY
 * @return PSA_ERROR_COMMUNICATION_FAILURE
 * @return PSA_ERROR_HARDWARE_FAILURE
 * @return PSA_ERROR_CORRUPTION_DETECTED
 * @return PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_hash_update(psa_hash_operation_t * operation,
                             const uint8_t * input,
                             size_t input_length);

/** @brief Finish the calculation of the hash of a message and compare it with
 * an expected value.
 *
 * The application must call psa_hash_setup() before calling this function.
 * This function calculates the hash of the message formed by concatenating
 * the inputs passed to preceding calls to psa_hash_update(). It then
 * compares the calculated hash with the expected hash passed as a
 * parameter to this function.
 *
 * When this function returns successfuly, the operation becomes inactive.
 * If this function returns an error status, the operation enters an error
 * state and must be aborted by calling psa_hash_abort().
 *
 * @note Implementations shall make the best effort to ensure that the
 * comparison between the actual hash and the expected hash is performed
 * in constant time.
 *
 * @param[in,out] operation     Active hash operation.
 * @param[in] hash              Buffer containing the expected hash value.
 * @param hash_length           Size of the \p hash buffer in bytes.
 *
 * @return PSA_SUCCESS
 *         The expected hash is identical to the actual hash of the message.
 * @return PSA_ERROR_INVALID_SIGNATURE
 *         The hash of the message was calculated successfully, but it
 *         differs from the expected hash.
 * @return PSA_ERROR_BAD_STATE
 *         The operation state is not valid (it must be active).
 * @return PSA_ERROR_INSUFFICIENT_MEMORY
 * @return PSA_ERROR_COMMUNICATION_FAILURE
 * @return PSA_ERROR_HARDWARE_FAILURE
 * @return PSA_ERROR_CORRUPTION_DETECTED
 * @return PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_hash_verify(psa_hash_operation_t * operation,
                             const uint8_t * hash,
                             size_t hash_length);

psa_status_t psa_import_key(const psa_key_attributes_t * attributes,
                            const uint8_t * data,
                            size_t data_length,
                            psa_key_id_t * key);

psa_key_attributes_t psa_key_attributes_init(void);
psa_status_t psa_key_derivation_abort(psa_key_derivation_operation_t * operation);
psa_status_t psa_key_derivation_get_capacity(const psa_key_derivation_operation_t * operation,
                                             size_t * capacity);
psa_status_t psa_key_derivation_input_bytes(psa_key_derivation_operation_t * operation,
                                            psa_key_derivation_step_t step,
                                            const uint8_t * data,
                                            size_t data_length);
psa_status_t psa_key_derivation_input_key(psa_key_derivation_operation_t * operation,
                                          psa_key_derivation_step_t step,
                                          psa_key_id_t key);
psa_status_t psa_key_derivation_key_agreement(psa_key_derivation_operation_t * operation,
                                              psa_key_derivation_step_t step,
                                              psa_key_id_t private_key,
                                              const uint8_t * peer_key,
                                              size_t peer_key_length);
psa_key_derivation_operation_t psa_key_derivation_operation_init(void);
psa_status_t psa_key_derivation_output_bytes(psa_key_derivation_operation_t * operation,
                                             uint8_t * output,
                                             size_t output_length);
psa_status_t psa_key_derivation_output_key(const psa_key_attributes_t * attributes,
                                           psa_key_derivation_operation_t * operation,
                                           psa_key_id_t * key);
psa_status_t psa_key_derivation_set_capacity(psa_key_derivation_operation_t * operation,
                                             size_t capacity);
psa_status_t psa_key_derivation_setup(psa_key_derivation_operation_t * operation,
                                      psa_algorithm_t alg);
psa_status_t psa_mac_abort(psa_mac_operation_t * operation);
psa_status_t psa_mac_compute(psa_key_id_t key,
                             psa_algorithm_t alg,
                             const uint8_t * input,
                             size_t input_length,
                             uint8_t * mac,
                             size_t mac_size,
                             size_t * mac_length);
psa_mac_operation_t psa_mac_operation_init(void);
psa_status_t psa_mac_sign_finish(psa_mac_operation_t * operation,
                                 uint8_t * mac,
                                 size_t mac_size,
                                 size_t * mac_length);
psa_status_t psa_mac_sign_setup(psa_mac_operation_t * operation,
                                psa_key_id_t key,
                                psa_algorithm_t alg);
psa_status_t psa_mac_update(psa_mac_operation_t * operation,
                            const uint8_t * input,
                            size_t input_length);
psa_status_t psa_mac_verify(psa_key_id_t key,
                            psa_algorithm_t alg,
                            const uint8_t * input,
                            size_t input_length,
                            const uint8_t * mac,
                            size_t mac_length);
psa_status_t psa_mac_verify_finish(psa_mac_operation_t * operation,
                                   const uint8_t * mac,
                                   size_t mac_length);
psa_status_t psa_mac_verify_setup(psa_mac_operation_t * operation,
                                  psa_key_id_t key,
                                  psa_algorithm_t alg);
psa_status_t psa_purge_key(psa_key_id_t key);
psa_status_t psa_raw_key_agreement(psa_algorithm_t alg,
                                   psa_key_id_t private_key,
                                   const uint8_t * peer_key,
                                   size_t peer_key_length,
                                   uint8_t * output,
                                   size_t output_size,
                                   size_t * output_length);
void psa_reset_key_attributes(psa_key_attributes_t * attributes);
void psa_set_key_algorithm(psa_key_attributes_t * attributes,
                           psa_algorithm_t alg);
void psa_set_key_bits(psa_key_attributes_t * attributes,
                      size_t bits);
void psa_set_key_id(psa_key_attributes_t * attributes,
                    psa_key_id_t id);
void psa_set_key_lifetime(psa_key_attributes_t * attributes,
                          psa_key_lifetime_t lifetime);
void psa_set_key_type(psa_key_attributes_t * attributes,
                      psa_key_type_t type);
void psa_set_key_usage_flags(psa_key_attributes_t * attributes,
                             psa_key_usage_t usage_flags);
psa_status_t psa_sign_hash(psa_key_id_t key,
                           psa_algorithm_t alg,
                           const uint8_t * hash,
                           size_t hash_length,
                           uint8_t * signature,
                           size_t signature_size,
                           size_t * signature_length);
psa_status_t psa_sign_message(psa_key_id_t key,
                              psa_algorithm_t alg,
                              const uint8_t * input,
                              size_t input_length,
                              uint8_t * signature,
                              size_t signature_size,
                              size_t * signature_length);
psa_status_t psa_verify_hash(psa_key_id_t key,
                             psa_algorithm_t alg,
                             const uint8_t * hash,
                             size_t hash_length,
                             const uint8_t * signature,
                             size_t signature_length);
psa_status_t psa_verify_message(psa_key_id_t key,
                                psa_algorithm_t alg,
                                const uint8_t * input,
                                size_t input_length,
                                const uint8_t * signature,
                                size_t signature_length);
#endif /* PSA_CRYPTO_H */
