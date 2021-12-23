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
#include <string.h>

#include "kernel_defines.h"

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
 * @brief Library initialization.
 *
 * Applications must call this function before calling any other function in this module.
 *
 * Applications are permitted to call this function more than once. Once a call succeeds,
 * subsequent calls are guaranteed to succeed.
 *
 * If the application calls other functions before calling psa_crypto_init(), the behavior is
 * undefined. In this situation:
 *
 *      - Implementations are encouraged to either perform the operation as if the library had
 *        been initialized or to return PSA_ERROR_BAD_STATE or some other applicable error.
 *
 *      - Implementations must not return a success status if the lack of initialization might
 *        have security implications, for example due to improper seeding of the random number
 *        generator.
 *
 *
 * @return      PSA_SUCCESS
 *              PSA_ERROR_INSUFFICIENT_MEMORY
 *              PSA_ERROR_COMMUNICATION_FAILURE
 *              PSA_ERROR_HARDWARE_FAILURE
 *              PSA_ERROR_CORRUPTION_DETECTED
 *              PSA_ERROR_INSUFFICIENT_ENTROPY
 */
psa_status_t psa_crypto_init(void);

/**
 * @brief Process an authenticated encryption operation.
 *
 * @param key                       Identifier of the key to use for the operation. It must allow
 *                                  the usage PSA_KEY_USAGE_ENCRYPT.
 * @param alg                       The AEAD algorithm to compute (PSA_ALG_XXX value such that
 *                                  PSA_ALG_IS_AEAD(alg) is true).
 * @param nonce                     Nonce or IV to use.
 * @param nonce_length              Size of the nonce buffer in bytes. This must be appropriate
 *                                  for the selected algorithm. The default nonce size is
 *                                  PSA_AEAD_NONCE_LENGTH(key_type, alg) where key_type is the
 *                                  type of key.
 * @param additional_data           Additional data that will be authenticated but not encrypted.
 * @param additional_data_length    Size of additional_data in bytes.
 * @param plaintext                 Data that will be authenticated and encrypted.
 * @param plaintext_length          Size of plaintext in bytes.
 * @param ciphertext                Output buffer for the authenticated and encrypted data. The
 *                                  additional data is not part of this output. For algorithms
 *                                  where the encrypted data and the authentication tag are defined
 *                                  as separate outputs, the authentication tag is appended to the
 *                                  encrypted data.
 * @param ciphertext_size           Size of the ciphertext buffer in bytes. This must be
 *                                  appropriate for the selected algorithm and key:
 *                                  - A sufficient output size is
 *                                    PSA_AEAD_ENCRYPT_OUTPUT_SIZE(key_type, alg, plaintext_length)
 *                                    where key_type is the type of key.
 *                                  - PSA_AEAD_ENCRYPT_OUTPUT_MAX_SIZE(plaintext_length) evaluates
 *                                    to the maximum ciphertext size of any supported AEAD
 *                                    encryption.
 * @param ciphertext_length         On success, the size of the output in the ciphertext buffer.
 *
 * @return  PSA_SUCCESS                          Success.
 *          PSA_ERROR_INVALID_HANDLE
 *          PSA_ERROR_NOT_PERMITTED              The key does not have the PSA_KEY_USAGE_ENCRYPT
 *                                              flag, or it does not permit the requested algorithm.
 *          PSA_ERROR_INVALID_ARGUMENT           key is not compatible with alg.
 *          PSA_ERROR_NOT_SUPPORTED              alg is not supported or is not an AEAD algorithm.
 *          PSA_ERROR_INSUFFICIENT_MEMORY
 *          PSA_ERROR_BUFFER_TOO_SMALL           ciphertext_size is too small.
 *                                              PSA_AEAD_ENCRYPT_OUTPUT_SIZE() or
 *                                              PSA_AEAD_ENCRYPT_OUTPUT_MAX_SIZE() can be used to
 *                                              determine the required buffer size.
 *          PSA_ERROR_COMMUNICATION_FAILURE
 *          PSA_ERROR_HARDWARE_FAILURE
 *          PSA_ERROR_CORRUPTION_DETECTED
 *          PSA_ERROR_STORAGE_FAILURE
 *          PSA_ERROR_DATA_CORRUPT
 *          PSA_ERROR_DATA_INVALID
 *          PSA_ERROR_BAD_STATE                  The library has not been previously initialized by
 *                                              psa_crypto_init(). It is implementation-dependent
 *                                              whether a failure to initialize results in this
 *                                              error code.
 */
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

/**
 * @brief Process an authenticated decryption operation.
 *
 * @param key                       Identifier of the key to use for the operation. It must allow
 *                                  the usage PSA_KEY_USAGE_DECRYPT.
 * @param alg                       The AEAD algorithm to compute (PSA_ALG_XXX value such that
 *                                  PSA_ALG_IS_AEAD(alg) is true).
 * @param nonce                     Nonce or IV to use.
 * @param nonce_length              Size of the nonce buffer in bytes. This must be appropriate
 *                                  for the selected algorithm. The default nonce size is
 *                                  PSA_AEAD_NONCE_LENGTH(key_type, alg) where key_type is the
 *                                  type of key.
 * @param additional_data           Additional data that will be authenticated but not encrypted.
 * @param additional_data_length    Size of additional_data in bytes.
 * @param ciphertext                Data that has been authenticated and encrypted. For algorithms
 *                                  where the encrypted data and the authentication tag are defined
 *                                  as separate inputs, the buffer must contain the encrypted data
 *                                  followed by the authentication tag.
 * @param ciphertext_length         Size of ciphertext in bytes.
 * @param plaintext                 Output buffer for the decrypted data.
 * @param plaintext_size            Size of the plaintext buffer in bytes. This must be
 *                                  appropriate for the selected algorithm and key:
 *                                  - A sufficient output size is
 *                                    PSA_AEAD_DECRYPT_OUTPUT_SIZE(key_type, alg, ciphertext_length)
 *                                    where key_type is the type of key.
 *                                  - PSA_AEAD_DECRYPT_OUTPUT_MAX_SIZE(ciphertext_length) evaluates
 *                                    to the maximum ciphertext size of any supported AEAD
 *                                    decryption.
 * @param plaintext_length          On success, the size of the output in the plaintext buffer.
 *
 * @return  PSA_SUCCESS                          Success.
 *          PSA_ERROR_INVALID_HANDLE
 *          PSA_ERROR_INVALID_SIGNATURE          The ciphertext is not authentic.
 *          PSA_ERROR_NOT_PERMITTED              The key does not have the PSA_KEY_USAGE_DECRYPT
 *                                              flag, or it does not permit the requested algorithm.
 *          PSA_ERROR_INVALID_ARGUMENT           key is not compatible with alg.
 *          PSA_ERROR_NOT_SUPPORTED              alg is not supported or is not an AEAD algorithm.
 *          PSA_ERROR_INSUFFICIENT_MEMORY
 *          PSA_ERROR_BUFFER_TOO_SMALL           plaintext_size is too small.
 *                                              PSA_AEAD_DECRYPT_OUTPUT_SIZE() or
 *                                              PSA_AEAD_DECRYPT_OUTPUT_MAX_SIZE() can be used to
 *                                              determine the required buffer size.
 *          PSA_ERROR_COMMUNICATION_FAILURE
 *          PSA_ERROR_HARDWARE_FAILURE
 *          PSA_ERROR_CORRUPTION_DETECTED
 *          PSA_ERROR_STORAGE_FAILURE
 *          PSA_ERROR_DATA_CORRUPT
 *          PSA_ERROR_DATA_INVALID
 *          PSA_ERROR_BAD_STATE                  The library has not been previously initialized by
 *                                              psa_crypto_init(). It is implementation-dependent
 *                                              whether a failure to initialize results in this
 *                                              error code.
 */
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

/**
 * @brief Return an initial value for an AEAD operation object.
 *
 * @return psa_aead_operation_t
 */
psa_aead_operation_t psa_aead_operation_init(void);

/**
 * @brief Set the key for a multi-part authenticated encryption operation.
 *
 * The sequence of operations to encrypt a message with authentication is as follows:
 *
 *      1. Allocate an operation object which will be passed to all the functions listed here
 *      2. Initialize the operation object with one of the methods described in the documentation
 *         for psa_aead_operation_t, e.g. PSA_AEAD_OPERATION_INIT.
 *      3. Call psa_aead_encrypt_setup() to specify the algorithm and key.
 *      4. If needed, call psa_aead_set_lengths() to specify the length of the inputs to the
 *         subsequent calls to psa_aead_update_ad() and psa_aead_update(). See the documentation
 *         of psa_aead_set_lengths() for details.
 *      5. Call either psa_aead_generate_nonce() or psa_aead_set_nonce() to generate or set the
 *         nonce. It is recommended to use psa_aead_generate_nonce() unless the protocol being
 *         implemented requires a specific nonce value.
 *      6. Call psa_aead_update_ad() zero, one or more times, passing a fragment of the
 *         non-encrypted additional authenticated data each time.
 *      7. Call psa_aead_update() zero, one or more times, passing a fragment of the message
 *         to encrypt each time.
 *      8. Call psa_aead_finish().
 *
 * If an error occurs at any step after a call to psa_aead_encrypt_setup(), the operation will need
 * to be reset by a call to psa_aead_abort(). The application can call psa_aead_abort() at any time
 * after the operation has been initialized.
 *
 * After a successful call to psa_aead_encrypt_setup(), the application must eventually terminate
 * the operation. The following events terminate an operation:
 *
 *      - A successful call to psa_aead_finish().
 *      - A call to psa_aead_abort().
 *
 * @param operation     The operation object to set up. It must have been initialized as per the
 *                      documentation for psa_aead_operation_t and not yet in use.
 * @param key           Identifier of the key to use for the operation. It must remain valid until
 *                      the operation terminates. It must allow the usage PSA_KEY_USAGE_ENCRYPT.
 * @param alg           The AEAD algorithm to compute (PSA_ALG_XXX value such that
 *                      PSA_ALG_IS_AEAD(alg) is true).
 *
 * @return  PSA_SUCCESS                          Success.
 *          PSA_ERROR_BAD_STATE                  The operation state is not valid:
 *                                              it must be inactive.
 *          PSA_ERROR_INVALID_HANDLE
 *          PSA_ERROR_NOT_PERMITTED              The key does not have the PSA_KEY_USAGE_ENCRYPT
 *                                              flag, or it does not permit the requested algorithm.
 *          PSA_ERROR_INVALID_ARGUMENT           key is not compatible with alg.
 *          PSA_ERROR_NOT_SUPPORTED              alg is not supported or is not an AEAD algorithm.
 *          PSA_ERROR_INSUFFICIENT_MEMORY
 *          PSA_ERROR_COMMUNICATION_FAILURE
 *          PSA_ERROR_HARDWARE_FAILURE
 *          PSA_ERROR_CORRUPTION_DETECTED
 *          PSA_ERROR_STORAGE_FAILURE
 *          PSA_ERROR_DATA_CORRUPT
 *          PSA_ERROR_DATA_INVALID
 *          PSA_ERROR_BAD_STATE                  The library has not been previously initialized by
 *                                              psa_crypto_init(). It is implementation-dependent
 *                                              whether a failure to initialize results in this
 *                                              error code.
 */
psa_status_t psa_aead_encrypt_setup(psa_aead_operation_t * operation,
                                    psa_key_id_t key,
                                    psa_algorithm_t alg);

/**
 * @brief Set the key for a multi-part authenticated decryption operation.
 *
 * The sequence of operations to decrypt a message with authentication is as follows:
 *
 *      1. Allocate an operation object which will be passed to all the functions listed here
 *      2. Initialize the operation object with one of the methods described in the documentation
 *         for psa_aead_operation_t, e.g. PSA_AEAD_OPERATION_INIT.
 *      3. Call psa_aead_decrypt_setup() to specify the algorithm and key.
 *      4. If needed, call psa_aead_set_lengths() to specify the length of the inputs to the
 *         subsequent calls to psa_aead_update_ad() and psa_aead_update(). See the documentation
 *         of psa_aead_set_lengths() for details.
 *      5. Call psa_aead_set_nonce() with the nonce for the decryption.
 *      6. Call psa_aead_update_ad() zero, one or more times, passing a fragment of the
 *         non-encrypted additional authenticated data each time.
 *      7. Call psa_aead_update() zero, one or more times, passing a fragment of the message
 *         to encrypt each time.
 *      8. Call psa_aead_verify().
 *
 * If an error occurs at any step after a call to psa_aead_decrypt_setup(), the operation will need
 * to be reset by a call to psa_aead_abort(). The application can call psa_aead_abort() at any time
 * after the operation has been initialized.
 *
 * After a successful call to psa_aead_decrypt_setup(), the application must eventually terminate
 * the operation. The following events terminate an operation:
 *
 *      - A successful call to psa_aead_verify().
 *      - A call to psa_aead_abort().
 *
 * @param operation     The operation object to set up. It must have been initialized as per the
 *                      documentation for psa_aead_operation_t and not yet in use.
 * @param key           Identifier of the key to use for the operation. It must remain valid until
 *                      the operation terminates. It must allow the usage PSA_KEY_USAGE_DECRYPT.
 * @param alg           The AEAD algorithm to compute (PSA_ALG_XXX value such that
 *                      PSA_ALG_IS_AEAD(alg) is true).
 *
 * @return  PSA_SUCCESS                          Success.
 *          PSA_ERROR_BAD_STATE                  The operation state is not valid:
 *                                              it must be inactive.
 *          PSA_ERROR_INVALID_HANDLE
 *          PSA_ERROR_NOT_PERMITTED              The key does not have the PSA_KEY_USAGE_DECRYPT
 *                                              flag, or it does not permit the requested algorithm.
 *          PSA_ERROR_INVALID_ARGUMENT           key is not compatible with alg.
 *          PSA_ERROR_NOT_SUPPORTED              alg is not supported or is not an AEAD algorithm.
 *          PSA_ERROR_INSUFFICIENT_MEMORY
 *          PSA_ERROR_COMMUNICATION_FAILURE
 *          PSA_ERROR_HARDWARE_FAILURE
 *          PSA_ERROR_CORRUPTION_DETECTED
 *          PSA_ERROR_STORAGE_FAILURE
 *          PSA_ERROR_DATA_CORRUPT
 *          PSA_ERROR_DATA_INVALID
 *          PSA_ERROR_BAD_STATE                  The library has not been previously initialized by
 *                                              psa_crypto_init(). It is implementation-dependent
 *                                              whether a failure to initialize results in this
 *                                              error code.
 */
psa_status_t psa_aead_decrypt_setup(psa_aead_operation_t * operation,
                                    psa_key_id_t key,
                                    psa_algorithm_t alg);

/**
 * @brief Declare the lengths of the message and additional data for AEAD.
 *
 * The application must call this function before calling psa_aead_set_nonce() or
 * psa_aead_generate_nonce(), if the algorithm for the operation requires it. If the algorithm does
 * not require it, calling this function is optional, but if this function is called then the
 * implementation must enforce the lengths.
 *
 *      - For PSA_ALG_CCM, calling this function is required.
 *      - For the other AEAD algorithms defined in this specification,
 *        calling this function is not required.
 *      - For vendor-defined algorithm, refer to the vendor documentation.
 *
 * If this function returns an error status, the operation enters an error state and must be
 * aborted by calling psa_aead_abort().
 *
 * @param operation             Active AEAD operation.
 * @param ad_length             Size of the non-encrypted additional authenticated data in bytes.
 * @param plaintext_length      Size of the plaintext to encrypt in bytes.
 *
 * @return  PSA_SUCCESS                          Success.
 *          PSA_ERROR_BAD_STATE                  The operation state is not valid: it must be
 *                                              active, and psa_aead_set_nonce() and
 *                                              psa_aead_generate_nonce() must not have been
 *                                              called yet.
 *          PSA_ERROR_INVALID_ARGUMENT           At least one of the lengths is not acceptable
 *                                              for the chosen algorithm.
 *          PSA_ERROR_INSUFFICIENT_MEMORY
 *          PSA_ERROR_COMMUNICATION_FAILURE
 *          PSA_ERROR_HARDWARE_FAILURE
 *          PSA_ERROR_CORRUPTION_DETECTED
 *          PSA_ERROR_BAD_STATE                  The library has not been previously initialized by
 *                                              psa_crypto_init(). It is implementation-dependent
 *                                              whether a failure to initialize results in this
 *                                              error code.
 */
psa_status_t psa_aead_set_lengths(psa_aead_operation_t * operation,
                                  size_t ad_length,
                                  size_t plaintext_length);

/**
 * @brief Generate a random nonce for an authenticated encryption operation.
 *
 * This function generates a random nonce for the authenticated encryption operation with an
 * appropriate size for the chosen algorithm, key type and key size.
 *
 * The application must call psa_aead_encrypt_setup() before calling this function. If applicable
 * for the algorithm, the application must call psa_aead_set_lengths() before calling this function.
 *
 * If this function returns an error status, the operation enters an error state and must be
 * aborted by calling psa_aead_abort().
 *
 * @param operation     Active AEAD operation.
 * @param nonce         Buffer where the generated nonce is to be written.
 * @param nonce_size    Size of the nonce buffer in bytes. This must be at least
 *                      PSA_AEAD_NONCE_LENGTH(key_type, alg) where key_type and
 *                      alg are type of key and the algorithm respectively that
 *                      were used to set up the AEAD operation.
 * @param nonce_length  On success, the number of bytes of the generated nonce.
 *
 * @return  PSA_SUCCESS                          Success.
 *          PSA_ERROR_BAD_STATE                  The operation state is not valid: it must be an
 *                                              active AEAD encryption operation, with no nonce set.
 *          PSA_ERROR_BAD_STATE                  The operation state is not valid: this is an
 *                                              algorithm which requires psa_aead_set_lengths() to
 *                                              be called before setting the nonce.
 *          PSA_ERROR_BUFFER_TOO_SMALL           The size of the nonce buffer is too small.
 *                                              PSA_AEAD_NONCE_LENGTH() or PSA_AEAD_NONCE_MAX_SIZE
 *                                              can be used to determine the required buffer size.
 *          PSA_ERROR_INSUFFICIENT_MEMORY
 *          PSA_ERROR_COMMUNICATION_FAILURE
 *          PSA_ERROR_HARDWARE_FAILURE
 *          PSA_ERROR_CORRUPTION_DETECTED
 *          PSA_ERROR_STORAGE_FAILURE
 *          PSA_ERROR_DATA_CORRUPT
 *          PSA_ERROR_DATA_INVALID
 *          PSA_ERROR_BAD_STATE                  The library has not been previously initialized by
 *                                              psa_crypto_init(). It is implementation-dependent
 *                                              whether a failure to initialize results in this
 *                                              error code.
 */
psa_status_t psa_aead_generate_nonce(psa_aead_operation_t * operation,
                                     uint8_t * nonce,
                                     size_t nonce_size,
                                     size_t * nonce_length);

/**
 * @brief Set the nonce for an authenticated encryption or decryption operation.
 *
 * This function sets the nonce for the authenticated encryption or decryption operation.
 * The application must call psa_aead_encrypt_setup() or psa_aead_decrypt_setup() before calling
 * this function. If applicable for the algorithm, the application must call psa_aead_set_lengths()
 * before calling this function.
 *
 * If this function returns an error status, the operation enters an error state and must be
 * aborted by calling psa_aead_abort().
 *
 * @note When encrypting, psa_aead_generate_nonce() is recommended instead of using this function,
 *       unless implementing a protocol that requires a non-random IV.
 *
 *
 * @param operation     Active AEAD operation.
 * @param nonce         Buffer containing the nonce to use.
 * @param nonce_length  Size of the nonce in bytes. This must be a valid nonce size for the chosen
 *                      algorithm. The default nonce size is PSA_AEAD_NONCE_LENGTH(key_type, alg)
 *                      where key_type and alg are type of key and the algorithm respectively that
 *                      were used to set up the AEAD operation.
 *
 * @return  PSA_SUCCESS                          Success.
 *          PSA_ERROR_BAD_STATE                  The operation state is not valid: it must be an
 *                                              active AEAD encryption operation, with no nonce set.
 *          PSA_ERROR_BAD_STATE                  The operation state is not valid: this is an
 *                                              algorithm which requires psa_aead_set_lengths() to
 *                                              be called before setting the nonce.
 *          PSA_ERROR_INVALID_ARGUMENT           The size of nonce is not acceptable for the chosen
 *                                              algorithm.
 *          PSA_ERROR_INSUFFICIENT_MEMORY
 *          PSA_ERROR_COMMUNICATION_FAILURE
 *          PSA_ERROR_HARDWARE_FAILURE
 *          PSA_ERROR_CORRUPTION_DETECTED
 *          PSA_ERROR_STORAGE_FAILURE
 *          PSA_ERROR_DATA_CORRUPT
 *          PSA_ERROR_DATA_INVALID
 *          PSA_ERROR_BAD_STATE                  The library has not been previously initialized by
 *                                              psa_crypto_init(). It is implementation-dependent
 *                                              whether a failure to initialize results in this
 *                                              error code.
 */
psa_status_t psa_aead_set_nonce(psa_aead_operation_t * operation,
                                const uint8_t * nonce,
                                size_t nonce_length);

/**
 * @brief Pass additional data to an active AEAD operation.
 *
 * Additional data is authenticated, but not encrypted.
 *
 * This function can be called multiple times to pass successive fragments of the additional data.
 * This function must not be called after passing data to encrypt or decrypt with psa_aead_update().
 *
 * The following must occur before calling this function:
 *      1. Call either psa_aead_encrypt_setup() or psa_aead_decrypt_setup().
 *      2. Set the nonce with psa_aead_generate_nonce() or psa_aead_set_nonce().
 *
 * If this function returns an error status, the operation enters an error state and must be
 * aborted by calling psa_aead_abort().
 *
 * @param operation     Active AEAD operation.
 * @param input         Buffer containing the fragment of additional data.
 * @param input_length  Size of the input buffer in bytes.
 *
 * @return  PSA_SUCCESS                          Success.
 *                                              @warning When decrypting, do not trust the input
 *                                                       until psa_aead_verify() succeeds.
 *                                                       See the detailed warning.
 *          PSA_ERROR_BAD_STATE                  The operation state is not valid: it must be
 *                                              active, have a nonce set, have lengths set if
 *                                              required by the algorithm, and psa_aead_update()
 *                                              must not have been called yet.
 *          PSA_ERROR_INVALID_ARGUMENT           The total input length overflows the additional
 *                                              data length that was previously specified with
 *                                              psa_aead_set_lengths().
 *          PSA_ERROR_INSUFFICIENT_MEMORY
 *          PSA_ERROR_COMMUNICATION_FAILURE
 *          PSA_ERROR_HARDWARE_FAILURE
 *          PSA_ERROR_CORRUPTION_DETECTED
 *          PSA_ERROR_STORAGE_FAILURE
 *          PSA_ERROR_DATA_CORRUPT
 *          PSA_ERROR_DATA_INVALID
 *          PSA_ERROR_BAD_STATE                  The library has not been previously initialized by
 *                                              psa_crypto_init(). It is implementation-dependent
 *                                              whether a failure to initialize results in this
 *                                              error code.
 */
psa_status_t psa_aead_update_ad(psa_aead_operation_t * operation,
                                const uint8_t * input,
                                size_t input_length);

/**
 * @brief Encrypt or decrypt a message fragment in an active AEAD operation.
 *
 * The following must occur before calling this function:
 *
 *      1. Call either psa_aead_encrypt_setup() or psa_aead_decrypt_setup(). The choice of setup
 *         function determines whether this function encrypts or decrypts its input.
 *      2. Set the nonce with psa_aead_generate_nonce() or psa_aead_set_nonce().
 *      3. Call psa_aead_update_ad() to pass all the additional data.
 *
 * If this function returns an error status, the operation enters an error state and must be
 * aborted by calling psa_aead_abort().
 *
 * This function does not require the input to be aligned to any particular block boundary. If the
 * implementation can only process a whole block at a time, it must consume all the input provided,
 * but it might delay the end of the corresponding output until a subsequent call to
 * psa_aead_update(), psa_aead_finish() or psa_aead_verify() provides sufficient input. The amount
 * of data that can be delayed in this way is bounded by PSA_AEAD_UPDATE_OUTPUT_SIZE().
 *
 * @param operation     Active AEAD operation.
 * @param input         Buffer containing the message fragment to encrypt or decrypt.
 * @param input_length  Size of the input buffer in bytes.
 * @param output        Buffer where the output is to be written.
 * @param output_size   Size of the output buffer in bytes. This must be appropriate for the
 *                      selected algorithm and key:
 *                      - A sufficient output size is PSA_AEAD_UPDATE_OUTPUT_SIZE(key_type, alg,
 *                        input_length) where key_type is the type of key and alg is the algorithm
 *                        that were used to set up the operation.
 *                      - PSA_AEAD_UPDATE_OUTPUT_MAX_SIZE(input_length) evaluates to the maximum
 *                        output size of any supported AEAD algorithm.
 * @param output_length On success, the number of bytes that make up the returned output.
 *
 * @return  PSA_SUCCESS                          Success.
 *                                              @warning When decrypting, do not trust the input
 *                                                       until psa_aead_verify() succeeds.
 *                                                       See the detailed warning.
 *          PSA_ERROR_BAD_STATE                  The operation state is not valid: it must be
 *                                              active, have a nonce set, and have lengths set if
 *                                              required by the algorithm.
 *          PSA_ERROR_BUFFER_TOO_SMALL           The size of the output buffer is too small.
 *                                              PSA_AEAD_UPDATE_OUTPUT_SIZE() or
 *                                              PSA_AEAD_UPDATE_OUTPUT_MAX_SIZE() can be used to
 *                                              determine the required buffer size.
 *          PSA_ERROR_INVALID_ARGUMENT           The total length of input to psa_aead_update_ad()
 *                                              so far is less than the additional data length that
 *                                              was previously specified with psa_aead_set_lengths()
 *          PSA_ERROR_INVALID_ARGUMENT           The total input length overflows the plaintext
 *                                              length that was previously specified with
 *                                              psa_aead_set_lengths().
 *          PSA_ERROR_INSUFFICIENT_MEMORY
 *          PSA_ERROR_COMMUNICATION_FAILURE
 *          PSA_ERROR_HARDWARE_FAILURE
 *          PSA_ERROR_CORRUPTION_DETECTED
 *          PSA_ERROR_STORAGE_FAILURE
 *          PSA_ERROR_DATA_CORRUPT
 *          PSA_ERROR_DATA_INVALID
 *          PSA_ERROR_BAD_STATE                  The library has not been previously initialized by
 *                                              psa_crypto_init(). It is implementation-dependent
 *                                              whether a failure to initialize results in this
 *                                              error code.
 */
psa_status_t psa_aead_update(psa_aead_operation_t * operation,
                             const uint8_t * input,
                             size_t input_length,
                             uint8_t * output,
                             size_t output_size,
                             size_t * output_length);

/**
 * @brief Finish encrypting a message in an AEAD operation.
 *
 * The operation must have been set up with psa_aead_encrypt_setup().
 *
 * This function finishes the authentication of the additional data formed by concatenating the
 * inputs passed to preceding calls to psa_aead_update_ad() with the plaintext formed by
 * concatenating the inputs passed to preceding calls to psa_aead_update().
 * This function has two output buffers:
 *      - ciphertext contains trailing ciphertext that was buffered from preceding calls to
 *        psa_aead_update().
 *      - tag contains the authentication tag.
 *
 * When this function returns successfully, the operation becomes inactive. If this function
 * returns an error status, the operation enters an error state and must be aborted by calling
 * psa_aead_abort().
 *
 * @param operation             Active AEAD operation.
 * @param ciphertext            Buffer where the last part of the ciphertext is to be written.
 * @param ciphertext_size       Size of the ciphertext buffer in bytes. This must be appropriate
 *                              for the selected algorithm and key:
 *                              - A sufficient output size is PSA_AEAD_FINISH_OUTPUT_SIZE(key_type,
 *                                alg) where key_type is the type of key and alg is the algorithm
 *                                that were used to set up the operation
 *                              - PSA_AEAD_FINISH_OUTPUT_MAX_SIZE evaluates to the maximum output
 *                                size of any supported AEAD algorithm.
 * @param ciphertext_length     On success, the number of bytes of returned ciphertext.
 * @param tag                   Buffer where the authentication tag is to be written.
 * @param tag_size              Size of the tag buffer in bytes. This must be appropriate for the
 *                              selected algorithm and key:
 *                              - The exact tag size is PSA_AEAD_TAG_LENGTH(key_type, key_bits,
 *                                alg) where key_type and key_bits are the type and bit-size of the
 *                                key, and alg is the algorithm that were used in the call to
 *                                psa_aead_encrypt_setup().
 *                              - PSA_AEAD_TAG_MAX_SIZE evaluates to the maximum tag size of any
 *                                supported AEAD algorithm.
 * @param tag_length            On success, the number of bytes that make up the returned tag.
 *
 * @return  PSA_SUCCESS                          Success.
 *          PSA_ERROR_BAD_STATE                  The operation state is not valid: it must be an
 *                                              active encryption operation with a nonce set.
 *          PSA_ERROR_BUFFER_TOO_SMALL           The size of the ciphertext or tag buffer is too
 *                                              small. PSA_AEAD_FINISH_OUTPUT_SIZE() or
 *                                              PSA_AEAD_FINISH_OUTPUT_MAX_SIZE can be used to
 *                                              determine the required ciphertext buffer size.
 *                                              PSA_AEAD_TAG_LENGTH() or PSA_AEAD_TAG_MAX_SIZE can
 *                                              be used to determine the required tag buffer size.
 *          PSA_ERROR_INVALID_ARGUMENT           The total length of input to psa_aead_update_ad()
 *                                              so far is less than the additional data length that
 *                                              was previously specified with psa_aead_set_lengths()
 *          PSA_ERROR_INVALID_ARGUMENT           The total length of input to psa_aead_update() so
 *                                              far is less than the plaintext length that was
 *                                              previously specified with psa_aead_set_lengths().
 *          PSA_ERROR_INSUFFICIENT_MEMORY
 *          PSA_ERROR_COMMUNICATION_FAILURE
 *          PSA_ERROR_HARDWARE_FAILURE
 *          PSA_ERROR_CORRUPTION_DETECTED
 *          PSA_ERROR_STORAGE_FAILURE
 *          PSA_ERROR_DATA_CORRUPT
 *          PSA_ERROR_DATA_INVALID
 *          PSA_ERROR_BAD_STATE                  The library has not been previously initialized by
 *                                              psa_crypto_init(). It is implementation-dependent
 *                                              whether a failure to initialize results in this
 *                                              error code.
 */
psa_status_t psa_aead_finish(psa_aead_operation_t * operation,
                             uint8_t * ciphertext,
                             size_t ciphertext_size,
                             size_t * ciphertext_length,
                             uint8_t * tag,
                             size_t tag_size,
                             size_t * tag_length);

/**
 * @brief Finish authenticating and decrypting a message in an AEAD operation.
 *
 * The operation must have been set up with psa_aead_decrypt_setup().
 *
 * This function finishes the authenticated decryption of the message components:
 *      - The additional data consisting of the concatenation of the inputs passed to preceding
 *        calls to psa_aead_update_ad().
 *      - The ciphertext consisting of the concatenation of the inputs passed to preceding calls to
 *        psa_aead_update().
 *      - The tag passed to this function call.
 *
 * If the authentication tag is correct, this function outputs any remaining plaintext
 * and reports success. If the authentication tag is not correct, this function returns
 * PSA_ERROR_INVALID_SIGNATURE.
 *
 * When this function returns successfully, the operation becomes inactive. If this function
 * returns an error status, the operation enters an error state and must be aborted by calling
 * psa_aead_abort().
 *
 * @note Implementations must make the best effort to ensure that the comparison between the actual
 *       tag and the expected tag is performed in constant time.
 *
 * @param operation             Active AEAD operation.
 * @param plaintext             Buffer where the last part of the plaintext is to be written. This
 *                              is the remaining data from previous calls to psa_aead_update() that
 *                              could not be processed until the end of the input.
 * @param plaintext_size        Size of the plaintext buffer in bytes. This must be appropriate
 *                              for the selected algorithm and key:
 *                              - A sufficient output size is PSA_AEAD_FINISH_OUTPUT_SIZE(key_type,
 *                                alg) where key_type is the type of key and alg is the algorithm
 *                                that were used to set up the operation
 *                              - PSA_AEAD_FINISH_OUTPUT_MAX_SIZE evaluates to the maximum output
 *                                size of any supported AEAD algorithm.
 * @param plaintext_length      On success, the number of bytes of returned plaintext.
 * @param tag                   Buffer containing the authentication tag.
 * @param tag_length            Size of the tag buffer in bytes.
 *
 * @return  PSA_SUCCESS                          Success.
 *          PSA_ERROR_INVALID_SIGNATURE          The calculations were successful, but the
 *                                              authentication tag is not correct.
 *          PSA_ERROR_BAD_STATE                  The operation state is not valid: it must be an
 *                                              active encryption operation with a nonce set.
 *          PSA_ERROR_BUFFER_TOO_SMALL           The size of the plaintext buffer is too small.
 *                                              PSA_AEAD_VERIFY_OUTPUT_SIZE() or
 *                                              PSA_AEAD_VERIFY_OUTPUT_MAX_SIZE can be used to
 *                                              determine the required buffer size.
 *          PSA_ERROR_INVALID_ARGUMENT           The total length of input to psa_aead_update_ad()
 *                                              so far is less than the additional data length that
 *                                              was previously specified with psa_aead_set_lengths()
 *          PSA_ERROR_INVALID_ARGUMENT           The total length of input to psa_aead_update() so
 *                                              far is less than the plaintext length that was
 *                                              previously specified with psa_aead_set_lengths().
 *          PSA_ERROR_INSUFFICIENT_MEMORY
 *          PSA_ERROR_COMMUNICATION_FAILURE
 *          PSA_ERROR_HARDWARE_FAILURE
 *          PSA_ERROR_CORRUPTION_DETECTED
 *          PSA_ERROR_STORAGE_FAILURE
 *          PSA_ERROR_DATA_CORRUPT
 *          PSA_ERROR_DATA_INVALID
 *          PSA_ERROR_BAD_STATE                  The library has not been previously initialized by
 *                                              psa_crypto_init(). It is implementation-dependent
 *                                              whether a failure to initialize results in this
 *                                              error code.
 */
psa_status_t psa_aead_verify(psa_aead_operation_t * operation,
                             uint8_t * plaintext,
                             size_t plaintext_size,
                             size_t * plaintext_length,
                             const uint8_t * tag,
                             size_t tag_length);

/**
 * @brief Abort an AEAD operation.
 *
 * Aborting an operation frees all associated resources except for the operation object itself.
 * Once aborted, the operation object can be reused for another operation by calling
 * psa_aead_encrypt_setup() or psa_aead_decrypt_setup() again.
 *
 * This function can be called any time after the operation object has been initialized as
 * described in psa_aead_operation_t.
 *
 * In particular, calling psa_aead_abort() after the operation has been terminated by a call to
 * psa_aead_abort(), psa_aead_finish() or psa_aead_verify() is safe and has no effect.
 *
 * @param operation             Initialized AEAD operation.
 *
 * @return  PSA_SUCCESS                          Success.
 *          PSA_ERROR_COMMUNICATION_FAILURE
 *          PSA_ERROR_HARDWARE_FAILURE
 *          PSA_ERROR_CORRUPTION_DETECTED
 *          PSA_ERROR_BAD_STATE                  The library has not been previously initialized by
 *                                              psa_crypto_init(). It is implementation-dependent
 *                                              whether a failure to initialize results in this
 *                                              error code.
 */
psa_status_t psa_aead_abort(psa_aead_operation_t * operation);

/**
 * @brief Encrypt a short message with a public key.
 *
 * For PSA_ALG_RSA_PKCS1V15_CRYPT, no salt is supported.
 *
 * @param key               Identifer of the key to use for the operation. It must be a
 *                          public key or an asymmetric key pair. It must allow the usage
 *                          PSA_KEY_USAGE_ENCRYPT.
 * @param alg               An asymmetric encryption algorithm that is compatible with
 *                          the type of key.
 * @param input             The message to encrypt.
 * @param input_length      Size of the input buffer in bytes.
 * @param salt              A salt or label, if supported by the encryption algorithm. If the
 *                          algorithm does not support a salt, pass NULL. If the algorithm supports
 *                          an optional salt, pass NULL to indicate that there is no salt.
 * @param salt_length       Size of the salt buffer in bytes. If salt is NULL, pass 0.
 * @param output            Buffer where the encrypted message is to be written.
 * @param output_size       Size of the output buffer in bytes. This must be appropriate for the
 *                          selected algorithm and key:
 *                          - The required output size is PSA_ASYMMETRIC_ENCRYPT_OUTPUT_SIZE
 *                            (key_type, key_bits, alg) where key_type and key_bits are the type
 *                            and bit-size respectively of key
 *                          - PSA_ASYMMETRIC_ENCRYPT_OUTPUT_MAX_SIZE evaluates to the maximum
 *                            output size of any supported asymmetric encryption.
 * @param output_length     On success, the number of bytes that make up the returned output.
 *
 * @return  PSA_SUCCESS
 *          PSA_ERROR_INVALID_HANDLE
 *          PSA_ERROR_NOT_PERMITTED          The key does not have the PSA_KEY_USAGE_ENCRYPT flag,
 *                                          or it does not permit the requested algorithm.
 *          PSA_ERROR_BUFFER_TOO_SMALL       The size of the output buffer is too small.
 *                                          PSA_ASYMMETRIC_ENCRYPT_OUTPUT_SIZE() or
 *                                          PSA_ASYMMETRIC_ENCRYPT_OUTPUT_MAX_SIZE can be used to
 *                                          determine the required buffer size.
 *          PSA_ERROR_NOT_SUPPORTED
 *          PSA_ERROR_INVALID_ARGUMENT
 *          PSA_ERROR_INSUFFICIENT_MEMORY
 *          PSA_ERROR_COMMUNICATION_FAILURE
 *          PSA_ERROR_HARDWARE_FAILURE
 *          PSA_ERROR_CORRUPTION_DETECTED
 *          PSA_ERROR_STORAGE_FAILURE
 *          PSA_ERROR_DATA_CORRUPT
 *          PSA_ERROR_DATA_INVALID
 *          PSA_ERROR_INSUFFICIENT_ENTROPY
 *          PSA_ERROR_BAD_STATE              The library has not been previously initialized by
 *                                          psa_crypto_init(). It is implementation-dependent
 *                                          whether a failure to initialize results in this error
 *                                          code.
 */
psa_status_t psa_asymmetric_encrypt(psa_key_id_t key,
                                    psa_algorithm_t alg,
                                    const uint8_t * input,
                                    size_t input_length,
                                    const uint8_t * salt,
                                    size_t salt_length,
                                    uint8_t * output,
                                    size_t output_size,
                                    size_t * output_length);

/**
 * @brief Decrypt a short message with a private key.
 *
 * For PSA_ALG_RSA_PKCS1V15_CRYPT, no salt is supported.
 *
 * @param key               Identifer of the key to use for the operation. It must be an asymmetric
 *                          key pair. It must allow the usage PSA_KEY_USAGE_DECRYPT.
 * @param alg               An asymmetric encryption algorithm that is compatible with
 *                          the type of key.
 * @param input             The message to decrypt.
 * @param input_length      Size of the input buffer in bytes.
 * @param salt              A salt or label, if supported by the encryption algorithm. If the
 *                          algorithm does not support a salt, pass NULL. If the algorithm supports
 *                          an optional salt, pass NULL to indicate that there is no salt.
 * @param salt_length       Size of the salt buffer in bytes. If salt is NULL, pass 0.
 * @param output            Buffer where the decrypted message is to be written.
 * @param output_size       Size of the output buffer in bytes. This must be appropriate for the
 *                          selected algorithm and key:
 *                          - The required output size is PSA_ASYMMETRIC_DECRYPT_OUTPUT_SIZE
 *                            (key_type, key_bits, alg) where key_type and key_bits are the type
 *                            and bit-size respectively of key.
 *                          - PSA_ASYMMETRIC_DECRYPT_OUTPUT_MAX_SIZE evaluates to the maximum
 *                            output size of any supported asymmetric decryption.
 * @param output_length     On success, the number of bytes that make up the returned output.
 *
 * @return  PSA_SUCCESS
 *          PSA_ERROR_INVALID_HANDLE
 *          PSA_ERROR_NOT_PERMITTED          The key does not have the PSA_KEY_USAGE_DECRYPT flag,
 *                                          or it does not permit the requested algorithm.
 *          PSA_ERROR_BUFFER_TOO_SMALL       The size of the output buffer is too small.
 *                                          PSA_ASYMMETRIC_DECRYPT_OUTPUT_SIZE() or
 *                                          PSA_ASYMMETRIC_DECRYPT_OUTPUT_MAX_SIZE can be used to
 *                                          determine the required buffer size.
 *          PSA_ERROR_NOT_SUPPORTED
 *          PSA_ERROR_INVALID_ARGUMENT
 *          PSA_ERROR_INSUFFICIENT_MEMORY
 *          PSA_ERROR_COMMUNICATION_FAILURE
 *          PSA_ERROR_HARDWARE_FAILURE
 *          PSA_ERROR_CORRUPTION_DETECTED
 *          PSA_ERROR_STORAGE_FAILURE
 *          PSA_ERROR_DATA_CORRUPT
 *          PSA_ERROR_DATA_INVALID
 *          PSA_ERROR_INSUFFICIENT_ENTROPY
 *          PSA_ERROR_INVALID_PADDING
 *          PSA_ERROR_BAD_STATE              The library has not been previously initialized by
 *                                          psa_crypto_init(). It is implementation-dependent
 *                                          whether a failure to initialize results in this error
 *                                          code.
 */
psa_status_t psa_asymmetric_decrypt(psa_key_id_t key,
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

/**
 * @brief Encrypt a message using a symmetric cipher.
 *
 * This function encrypts a message with a random initialization vector (IV). The length of the IV
 * is PSA_CIPHER_IV_LENGTH(key_type, alg) where key_type is the type of key. The output of
 * psa_cipher_encrypt() is the IV followed by the ciphertext.
 *
 * Use the multi-part operation interface with a psa_cipher_operation_t object to provide other
 * forms of IV or to manage the IV and ciphertext independently.
 *
 * @param key           Identifier of the key to use for the operation. It must allow the usage
 *                      PSA_KEY_USAGE_ENCRYPT.
 * @param alg           The cipher algorithm to compute (PSA_ALG_XXX value such that
 *                      PSA_ALG_IS_CIPHER(alg) is true).
 * @param input         Buffer containing the message to encrypt.
 * @param input_length  Size of the input buffer in bytes.
 * @param output        Buffer where the output is to be written. The output contains the IV
 *                      followed by the ciphertext proper.
 * @param output_size   Size of the output buffer in bytes. This must be appropriate for the
 *                      selected algorithm and key:
 *                          - A sufficient output size is PSA_CIPHER_ENCRYPT_OUTPUT_SIZE(key_type,
 *                            alg, input_length) where key_type is the type of key
 *                          - PSA_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE(input_length) evaluates to the
 *                            maximum output size of any supported cipher encryption.
 * @param output_length On success, the number of bytes that make up the output.
 *
 * @return  PSA_SUCCESS
 *              Success.
 *          PSA_ERROR_INVALID_HANDLE
 *          PSA_ERROR_NOT_PERMITTED
 *              The key does not have the PSA_KEY_USAGE_ENCRYPT flag, or it does not permit the
 *              requested algorithm.
 *          PSA_ERROR_INVALID_ARGUMENT
 *              key is not compatible with alg.
 *          PSA_ERROR_INVALID_ARGUMENT
 *              The input_length is not valid for the algorithm and key type. For example, the
 *              algorithm is a based on block cipher and requires a whole number of blocks, but the
 *              total input size is not a multiple of the block size.
 *          PSA_ERROR_NOT_SUPPORTED
 *              alg is not supported or is not a cipher algorithm.
 *          PSA_ERROR_BUFFER_TOO_SMALL
 *              output_size is too small. PSA_CIPHER_ENCRYPT_OUTPUT_SIZE() or
 *          PSA_CIPHER_ENCRYPT_OUTPUT_MAX_SIZE() can be used to determine the required buffer size.
 *          PSA_ERROR_INSUFFICIENT_MEMORY
 *          PSA_ERROR_COMMUNICATION_FAILURE
 *          PSA_ERROR_HARDWARE_FAILURE
 *          PSA_ERROR_CORRUPTION_DETECTED
 *          PSA_ERROR_STORAGE_FAILURE
 *          PSA_ERROR_DATA_CORRUPT
 *          PSA_ERROR_DATA_INVALID
 *          PSA_ERROR_BAD_STATE
 *              The library has not been previously initialized by psa_crypto_init(). It is
 *              implementation-dependent whether a failure to initialize results in this error code.
 */
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

/**
 * @brief Generate an initialization vector (IV) for a symmetric encryption operation.
 *
 * This function generates a random IV, nonce or initial counter value for the encryption
 * operation as appropriate for the chosen algorithm, key type and key size.
 *
 * The generated IV is always the default length for the key and algorithm: PSA_CIPHER_IV_LENGTH
 * (key_type, alg), where key_type is the type of key and alg is the algorithm that were used to
 * set up the operation. To generate different lengths of IV, use psa_generate_random() and
 * psa_cipher_set_iv().
 *
 * If the cipher algorithm does not use an IV, calling this function returns a PSA_ERROR_BAD_STATE  * error. For these algorithms, PSA_CIPHER_IV_LENGTH(key_type, alg) will be zero.
 *
 * The application must call psa_cipher_encrypt_setup() before calling this function.
 *
 * If this function returns an error status, the operation enters an error state and must be
 * aborted by calling psa_cipher_abort().
 *
 * @param operation Active cipher operation.
 * @param iv        Buffer where the generated IV is to be written.
 * @param iv_size   Size of the iv buffer in bytes. This must be at least
 *                  PSA_CIPHER_IV_LENGTH(key_type, alg) where key_type and
 *                  alg are type of key and the algorithm respectively that
 *                  were used to set up the cipher operation.
 * @param iv_length On success, the number of bytes of the generated IV.
 *
 * @return  PSA_SUCCESS
 *          Success.
 *          PSA_ERROR_BAD_STATE
 *          Either:
 *          - The cipher algorithm does not use an IV.
 *          - The operation state is not valid: it must be active, with no IV set.
 *          PSA_ERROR_BUFFER_TOO_SMALL
 *          The size of the iv buffer is too small. PSA_CIPHER_IV_LENGTH() or
 *          PSA_CIPHER_IV_MAX_SIZE can be used to determine the required buffer size.
 *          PSA_ERROR_INSUFFICIENT_MEMORY
 *          PSA_ERROR_COMMUNICATION_FAILURE
 *          PSA_ERROR_HARDWARE_FAILURE
 *          PSA_ERROR_CORRUPTION_DETECTED
 *          PSA_ERROR_STORAGE_FAILURE
 *          PSA_ERROR_DATA_CORRUPT
 *          PSA_ERROR_DATA_INVALID
 *          PSA_ERROR_BAD_STATE
 *          The library has not been previously initialized by psa_crypto_init(). It is
 *          implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_cipher_generate_iv(psa_cipher_operation_t * operation,
                                    uint8_t * iv,
                                    size_t iv_size,
                                    size_t * iv_length);
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
psa_status_t psa_builtin_export_public_key(  const psa_key_attributes_t *attributes,
                                                    uint8_t *key_buffer,
                                                    size_t key_buffer_size,
                                                    uint8_t * data,
                                                    size_t data_size,
                                                    size_t * data_length);
psa_status_t psa_export_public_key(psa_key_id_t key,
                                   uint8_t * data,
                                   size_t data_size,
                                   size_t * data_length);

psa_status_t psa_builtin_generate_key(const psa_key_attributes_t *attributes, uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length);

/**
 * @brief Generate a key or key pair.
 *
 * @param attributes        The attributes for the new key. This function uses the attributes as follows:
 *                              - The key type is required. It cannot be an asymmetric public key.
 *                              - The key size is required. It must be a valid size for the key type.
 *                              - The key permitted-algorithm policy is required for keys that will be
 *                                used for a cryptographic operation, see Permitted algorithms.
 *                              - The key usage flags define what operations are permitted with the key,
 *                                see Key usage flags.
 *                              - The key lifetime and identifier are required for a persistent key.
 *                          @note This is an input parameter: it is not updated with the final key attributes.
 *                                The final attributes of the new key can be queried by calling
 *                                psa_get_key_attributes() with the key’s identifier.
 * @param key               On success, an identifier for the newly created key. PSA_KEY_ID_NULL on failure.
 *
 * @return  PSA_SUCCESS                     Success. If the key is persistent, the key material
 *                                          and the key’s metadata have been saved to persistent
 *                                          storage.
 *          PSA_ERROR_ALREADY_EXISTS        This is an attempt to create a persistent key, and
 *                                          there is already a persistent key with the given
 *                                          identifier.
 *          PSA_ERROR_NOT_SUPPORTED         The key type or key size is not supported, either by
 *                                          the implementation in general or in this particular
 *                                          persistent location.
 *          PSA_ERROR_INVALID_ARGUMENT       The key attributes, as a whole, are invalid.
 *          PSA_ERROR_INVALID_ARGUMENT       The key type is an asymmetric public key type.
 *          PSA_ERROR_INVALID_ARGUMENT       The key size is not a valid size for the key type.
 *          PSA_ERROR_INSUFFICIENT_MEMORY
 *          PSA_ERROR_INSUFFICIENT_ENTROPY
 *          PSA_ERROR_COMMUNICATION_FAILURE
 *          PSA_ERROR_HARDWARE_FAILURE
 *          PSA_ERROR_CORRUPTION_DETECTED
 *          PSA_ERROR_INSUFFICIENT_STORAGE
 *          PSA_ERROR_STORAGE_FAILURE
 *          PSA_ERROR_DATA_CORRUPT
 *          PSA_ERROR_DATA_INVALID
 *          PSA_ERROR_BAD_STATE              The library has not been previously initialized by
 *                                          psa_crypto_init(). It is implementation-dependent
 *                                          whether a failure to initialize results in this error
 *                                          code.
 */
psa_status_t psa_generate_key(const psa_key_attributes_t * attributes,
                              psa_key_id_t * key);

psa_status_t psa_builtin_generate_random(   uint8_t * output,
                                            size_t output_size);
psa_status_t psa_generate_random(uint8_t * output,
                                 size_t output_size);

/**
 * @brief Declare the permitted algorithm policy for a key.
 *
 * The permitted algorithm policy of a key encodes which algorithm or algorithms are permitted to
 * be used with this key.
 * This function overwrites any permitted algorithm policy previously set in attributes.
 *
 * @param attributes    The attribute object to write to.
 * @param alg           The permitted algorithm to write.
 */
static inline void psa_set_key_algorithm(psa_key_attributes_t * attributes,
                           psa_algorithm_t alg)
{
    attributes->policy.alg = alg;
}

/**
 * @brief Retrieve the permitted algorithm policy from key attributes.
 *
 * @param attributes    The key attribute object to query.
 *
 * @return psa_status_t The algorithm stored in the attribute object.
 */
static inline psa_algorithm_t psa_get_key_algorithm(const psa_key_attributes_t * attributes)
{
    return attributes->policy.alg;
}

/**
 * @brief Declare the size of a key.
 *
 * This function overwrites any key size previously set in attributes.
 *
 * @param attributes    The attribute object to write to.
 * @param bits          The key size in bits. If this is 0,
 *                      the key size in attributes becomes
 *                      unspecified. Keys of size 0 are not supported.
 */
static inline void psa_set_key_bits(psa_key_attributes_t * attributes,
                      size_t bits)
{
    attributes->bits = bits;
}

/**
 * @brief Retrieve the key size from key attributes.
 *
 * @param attributes    The key attribute object to query.
 *
 * @return size_t       The key size stored in the attribute object, in bits.
 */
static inline size_t psa_get_key_bits(const psa_key_attributes_t * attributes)
{
    return attributes->bits;
}

/**
 * @brief Declare a key as persistent and set its key identifier.
 *
 * The application must choose a value for id between PSA_KEY_ID_USER_MIN and PSA_KEY_ID_USER_MAX.
 * If the attribute object currently declares the key as volatile, which is the default lifetime of
 * an attribute object, this function sets the lifetime attribute to PSA_KEY_LIFETIME_PERSISTENT.
 *
 * This function does not access storage, it merely stores the given value in the attribute object.
 * The persistent key will be written to storage when the attribute object is passed to a key
 * creation function such as psa_import_key(), psa_generate_key(), psa_key_derivation_output_key()
 * or psa_copy_key().
 *
 * @param attributes    The attribute object to write to.
 * @param id            The persistent identifier for the key.
 */
static inline void psa_set_key_id(psa_key_attributes_t * attributes, psa_key_id_t id)
{
    attributes->id = id;
}

/**
 * @brief Retrieve the key identifier from key attributes.
 *
 * @param attributes    The key attribute object to query.
 *
 * @return psa_key_id_t The persistent identifier stored in the attribute object.
 *                      This value is unspecified if the attribute object declares
 *                      the key as volatile.
 */
static inline psa_key_id_t psa_get_key_id(const psa_key_attributes_t * attributes)
{
    return attributes->id;
}

/**
 * @brief Set the location of a persistent key.
 *
 * To make a key persistent, give it a persistent key identifier by using psa_set_key_id().
 * By default, a key that has a persistent identifier is stored in the default storage area
 * identifier by PSA_KEY_LIFETIME_PERSISTENT. Call this function to choose a storage area,
 * or to explicitly declare the key as volatile.
 *
 * This function does not access storage, it merely stores the given value in the attribute object.
 * The persistent key will be written to storage when the attribute object is passed to a key
 * creation function such as psa_import_key(), psa_generate_key(), psa_key_derivation_output_key()
 * or psa_copy_key().
 *
 * @param attributes    The attribute object to write to.
 * @param lifetime      The lifetime for the key. If this is PSA_KEY_LIFETIME_VOLATILE,
 *                      the key will be volatile, and the key identifier attribute is reset
 *                      to PSA_KEY_ID_NULL.
 */
static inline void psa_set_key_lifetime(psa_key_attributes_t * attributes,
                          psa_key_lifetime_t lifetime)
{
    attributes->lifetime = lifetime;
}

/**
 * @brief Retrieve the lifetime from key attributes.
 *
 * @param attributes            The key attribute object to query.
 *
 * @return psa_key_lifetime_t   The lifetime value stored in the attribute object.
 */
static inline psa_key_lifetime_t psa_get_key_lifetime(const psa_key_attributes_t * attributes)
{
    return attributes->lifetime;
}

/**
 * @brief Declare the type of a key.
 *
 * This function overwrites any key type previously set in attributes.
 *
 * @param attributes    The attribute object to write to.
 * @param type          The key type to write. If this is PSA_KEY_TYPE_NONE,
 *                      the key type in attributes becomes unspecified.
 */
static inline void psa_set_key_type(psa_key_attributes_t * attributes,
                      psa_key_type_t type)
{
    attributes->type = type;
}

/**
 * @brief Retrieve the key type from key attributes.
 *
 * @param attributes        The key attribute object to query.
 *
 * @return psa_key_type_t   The key type stored in the attribute object.
 */
static inline psa_key_type_t psa_get_key_type(const psa_key_attributes_t * attributes)
{
    return attributes->type;
}

/**
 * @brief Declare usage flags for a key.
 *
 * Usage flags are part of a key’s policy. They encode what kind of operations are
 * permitted on the key. For more details, see Key policies.
 *
 * This function overwrites any usage flags previously set in attributes.
 *
 * @param attributes    The attribute object to write to.
 * @param usage_flags   The usage flags to write.
 */
static inline void psa_set_key_usage_flags(psa_key_attributes_t * attributes,
                             psa_key_usage_t usage_flags)
{
    attributes->policy.usage = usage_flags;
}

/**
 * @brief Retrieve the usage flags from key attributes.
 *
 * @param attributes        The key attribute object to query.
 *
 * @return psa_key_usage_t  The usage flags stored in the attribute object.
 */
static inline psa_key_usage_t psa_get_key_usage_flags(const psa_key_attributes_t * attributes)
{
    return attributes->policy.usage;
}

/**
 * @brief Reset a key attribute object to a freshly initialized state.
 *
 * The attribute object must be initialized as described in the documentation of the type
 * psa_key_attributes_t before calling this function. Once the object has been initialized, this
 * function can be called at any time.
 *
 * This function frees any auxiliary resources that the object might contain.
 *
 * @param attributes    The attribute object to reset.
 */
static inline void psa_reset_key_attributes(psa_key_attributes_t * attributes)
{
    *attributes = psa_key_attributes_init();
}

/**
 * @brief Retrieve the attributes of a key.
 *
 * This function first resets the attribute object as with psa_reset_key_attributes().
 * It then copies the attributes of the given key into the given attribute object.
 *
 * @note    This function clears any previous content from the attribute object and therefore
 *          expects it to be in a valid state. In particular, if this function is called on a newly
 *          allocated attribute object, the attribute object must be initialized before calling
 *          this function.
 *
 * @note    This function might allocate memory or other resources. Once this function has been
 *          called on an attribute object, psa_reset_key_attributes() must be called to free these
 *          resources.
 *
 * @param key           Identifier of the key to query.
 * @param attributes    On entry, *attributes must be in a valid state. On successful return,
 *                      it contains the attributes of the key. On failure, it is equivalent
 *                      to a freshly-initialized attribute object.
 *
 * @return  PSA_SUCCESS
 *          PSA_ERROR_INVALID_HANDLE
 *          PSA_ERROR_INSUFFICIENT_MEMORY
 *          PSA_ERROR_COMMUNICATION_FAILURE
 *          PSA_ERROR_CORRUPTION_DETECTED
 *          PSA_ERROR_STORAGE_FAILURE
 *          PSA_ERROR_DATA_CORRUPT
 *          PSA_ERROR_DATA_INVALID
 *          PSA_ERROR_BAD_STATE
 *          The library has not been previously initialized by psa_crypto_init(). It is
 *          implementation-dependent whether a failure to initialize results in this error code.
 */
psa_status_t psa_get_key_attributes(psa_key_id_t key,
                                    psa_key_attributes_t * attributes);

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
 *         PSA_ERROR_COMMUNICATION_FAILURE
 *         PSA_ERROR_HARDWARE_FAILURE
 *         PSA_ERROR_CORRUPTION_DETECTED
 *         PSA_ERROR_BAD_STATE
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
 *         PSA_ERROR_BAD_STATE
 *         The source_operation state is not valid (it must be active).
 *         PSA_ERROR_BAD_STATE
 *         The target_operation state is not valid (it must be inactive).
 *         PSA_ERROR_COMMUNICATION_FAILURE
 *         PSA_ERROR_HARDWARE_FAILURE
 *         PSA_ERROR_CORRUPTION_DETECTED
 *         PSA_ERROR_INSUFFICIENT_MEMORY
 *         PSA_ERROR_BAD_STATE
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
 *                          such that #PSA_ALG_IS_HASH(alg) is true).
 * @param[in] input         Buffer containing the message to hash.
 * @param input_length      Size of the input buffer in bytes.
 * @param[out] hash         Buffer containing the expected hash value.
 * @param hash_length       Size of the hash buffer in bytes.
 *
 * @return PSA_SUCCESS
 *         The expected hash is identical to the actual hash of the input.
 *         PSA_ERROR_INVALID_SIGNATURE
 *         The hash of the message was calculated successfully, but it
 *         differs from the expected hash.
 *         PSA_ERROR_NOT_SUPPORTED
 *         alg is not supported or is not a hash algorithm.
 *         PSA_ERROR_INVALID_ARGUMENT
 *         input_length or hash_length do not match the hash size for alg
 *         PSA_ERROR_INSUFFICIENT_MEMORY
 *         PSA_ERROR_COMMUNICATION_FAILURE
 *         PSA_ERROR_HARDWARE_FAILURE
 *         PSA_ERROR_CORRUPTION_DETECTED
 *         PSA_ERROR_INSUFFICIENT_MEMORY
 *         PSA_ERROR_BAD_STATE
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
 *         PSA_ERROR_NOT_SUPPORTED
 *         alg is not supported or is not a hash algorithm.
 *         PSA_ERROR_INVALID_ARGUMENT
 *         PSA_ERROR_BUFFER_TOO_SMALL
 *         hash_size is too small
 *         PSA_ERROR_INSUFFICIENT_MEMORY
 *         PSA_ERROR_COMMUNICATION_FAILURE
 *         PSA_ERROR_HARDWARE_FAILURE
 *         PSA_ERROR_CORRUPTION_DETECTED
 *         PSA_ERROR_INSUFFICIENT_MEMORY
 *         PSA_ERROR_BAD_STATE
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
 *         PSA_ERROR_BAD_STATE
 *         The operation state is not valid (it must be active).
 *         PSA_ERROR_BUFFER_TOO_SMALL
 *         The size of the hash buffer is too small. You can determine a
 *         sufficient buffer size by calling #PSA_HASH_LENGTH(\c alg)
 *         where \c alg is the hash algorithm that is calculated.
 *         PSA_ERROR_INSUFFICIENT_MEMORY
 *         PSA_ERROR_COMMUNICATION_FAILURE
 *         PSA_ERROR_HARDWARE_FAILURE
 *         PSA_ERROR_CORRUPTION_DETECTED
 *         PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_hash_finish(psa_hash_operation_t * operation,
                             uint8_t * hash,
                             size_t hash_size,
                             size_t * hash_length);

/**
 * Return an initial value for a hash operation object.
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
 *                          such that #PSA_ALG_IS_HASH(alg) is true).
 *
 * @return PSA_SUCCESS
 *         Success.
 *         PSA_ERROR_NOT_SUPPORTED
 *         alg is not a supported hash algorithm.
 *         PSA_ERROR_INVALID_ARGUMENT
 *         alg is not a hash algorithm.
 *         PSA_ERROR_BAD_STATE
 *         The operation state is not valid (it must be inactive).
 *         PSA_ERROR_INSUFFICIENT_MEMORY
 *         PSA_ERROR_COMMUNICATION_FAILURE
 *         PSA_ERROR_HARDWARE_FAILURE
 *         PSA_ERROR_CORRUPTION_DETECTED
 *         PSA_ERROR_BAD_STATE
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
 *         PSA_ERROR_BAD_STATE
 *         The operation state is not valid (it muct be active).
 *         PSA_ERROR_INSUFFICIENT_MEMORY
 *         PSA_ERROR_COMMUNICATION_FAILURE
 *         PSA_ERROR_HARDWARE_FAILURE
 *         PSA_ERROR_CORRUPTION_DETECTED
 *         PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_hash_update(psa_hash_operation_t * operation,
                             const uint8_t * input,
                             size_t input_length);

/**
 * @brief Finish the calculation of the hash of a message and compare it with
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
 *         PSA_ERROR_INVALID_SIGNATURE
 *         The hash of the message was calculated successfully, but it
 *         differs from the expected hash.
 *         PSA_ERROR_BAD_STATE
 *         The operation state is not valid (it must be active).
 *         PSA_ERROR_INSUFFICIENT_MEMORY
 *         PSA_ERROR_COMMUNICATION_FAILURE
 *         PSA_ERROR_HARDWARE_FAILURE
 *         PSA_ERROR_CORRUPTION_DETECTED
 *         PSA_ERROR_BAD_STATE
 *         The library has not been previously initialized by psa_crypto_init().
 *         It is implementation-dependent whether a failure to initialize
 *         results in this error code.
 */
psa_status_t psa_hash_verify(psa_hash_operation_t * operation,
                             const uint8_t * hash,
                             size_t hash_length);

psa_status_t psa_builtin_import_key(const psa_key_attributes_t *attributes,
                                    const uint8_t *data, size_t data_length,
                                    uint8_t *key_buffer, size_t key_buffer_size,
                                    size_t *key_buffer_length, size_t *bits);

/**
 * @brief Import a key in binary format.
 *
 * This function supports any output from psa_export_key(). Refer to the documentation of
 * psa_export_public_key() for the format of public keys and to the documentation of
 * psa_export_key() for the format for other key types.
 *
 * The key data determines the key size. The attributes can optionally specify a key size;
 * in this case it must match the size determined from the key data. A key size of 0 in
 * attributes indicates that the key size is solely determined by the key data.
 *
 * Implementations must reject an attempt to import a key of size 0.
 *
 * This specification defines a single format for each key type. Implementations can optionally
 * support other formats in addition to the standard format. It is recommended that implementations
 * that support other formats ensure that the formats are clearly unambiguous, to minimize the risk
 * that an invalid input is accidentally interpreted according to a different format.
 *
 * @note The PSA Crypto API does not support asymmetric private key objects outside of a key pair.
 * To import a private key, the attributes must specify the corresponding key pair type. Depending
 * on the key type, either the import format contains the public key data or the implementation
 * will reconstruct the public key from the private key as needed.
 *
 * @param attributes            The attributes for the new key.
 *                              This function uses the attributes as follows:
 *                                  - The key type is required, and determines
 *                                    how the data buffer is interpreted.
 *                                  - The key size is always determined from the
 *                                    data buffer. If the key size in attributes
 *                                    is nonzero, it must be equal to the size
 *                                    determined from data.
 *                                  - The key permitted-algorithm policy is required
 *                                    for keys that will be used for a cryptographic
 *                                    operation, see Permitted algorithms.
 *                                  - The key usage flags define what operations are
 *                                    permitted with the key, see Key usage flags.
 *                                  - The key lifetime and identifier are required
 *                                    for a persistent key.
 *                              @note This is an input parameter: it is not updated with the final
 *                              key attributes. The final attributes of the new key can be queried
 *                              by calling psa_get_key_attributes() with the key’s identifier.
 *
 * @param data                  Buffer containing the key data. The content of this buffer is
 *                              interpreted according to the type declared in attributes. All
 *                              implementations must support at least the format described in the
 *                              documentation of psa_export_key() or psa_export_public_key() for
 *                              the chosen type. Implementations can support other formats, but be
 *                              conservative in interpreting the key data: it is recommended that
 *                              implementations reject content if it might be erroneous, for
 *                              example, if it is the wrong type or is truncated.
 * @param data_length           Size of the data buffer in bytes.
 * @param key                   On success, an identifier for the newly created key.
 *                              PSA_KEY_ID_NULL on failure.
 *
 * @return  PSA_SUCCESS
 *          Success. If the key is persistent, the key material and the key’s metadata have been
 *          saved to persistent storage.
 *          PSA_ERROR_ALREADY_EXISTS
 *          This is an attempt to create a persistent key, and there is already a persistent key
 *          with the given identifier.
 *          PSA_ERROR_NOT_SUPPORTED
 *          The key type or key size is not supported, either by the implementation in general or
 *          in this particular persistent location.
 *          PSA_ERROR_INVALID_ARGUMENT
 *          The key attributes, as a whole, are invalid.
 *          PSA_ERROR_INVALID_ARGUMENT
 *          The key data is not correctly formatted.
 *          PSA_ERROR_INVALID_ARGUMENT
 *          The size in attributes is nonzero and does not match the size of the key data.
 *          PSA_ERROR_INSUFFICIENT_MEMORY
 *          PSA_ERROR_INSUFFICIENT_STORAGE
 *          PSA_ERROR_COMMUNICATION_FAILURE
 *          PSA_ERROR_STORAGE_FAILURE
 *          PSA_ERROR_DATA_CORRUPT
 *          PSA_ERROR_DATA_INVALID
 *          PSA_ERROR_HARDWARE_FAILURE
 *          PSA_ERROR_CORRUPTION_DETECTED
 *          PSA_ERROR_BAD_STATE
 *          The library has not been previously initialized by psa_crypto_init(). It is
 *          implementation-dependent whether a failure to initialize results in this error code.
 *
 */
psa_status_t psa_import_key(const psa_key_attributes_t * attributes,
                            const uint8_t * data,
                            size_t data_length,
                            psa_key_id_t * key);

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

/**
 * @brief Verify the signature of a hash or short message using a public key.
 *
 * With most signature mechanisms that follow the hash-and-sign paradigm, the hash input to this function is the hash
 * of the message to sign. The hash algorithm is encoded in the signature algorithm.
 * Some hash-and-sign mechanisms apply a padding or encoding to the hash. In such cases, the encoded hash must be
 * passed to this function. The current version of this specification defines one such signature algorithm:
 * PSA_ALG_RSA_PKCS1V15_SIGN_RAW.
 *
 * @note To perform a hash-and-sign verification algorithm, the hash must be calculated before passing it to this
 * function. This can be done by calling psa_hash_compute() or with a multi-part hash operation. Alternatively, to hash
 * and verify a message signature in a single call, use psa_verify_message().
 *
 * @note When using secure elements as backends in this implementation, the key type can only be of type
 * PSA_KEY_TYPE_ECC_PUBLIC_KEY(curve) and must be stored on a secure element. To use the public key of a previously
 * generated key pair, please export the public key first and then import it as a separate key with its own attributes
 * and identifier.
 *
 * @param key               Identifier of the key to use for the operation. It must be a public key or an asymmetric
 *                          key pair. The key must allow the usage PSA_KEY_USAGE_VERIFY_HASH.
 * @param alg               An asymmetric signature algorithm that separates the hash and sign operations (PSA_ALG_XXX
 *                          value such that PSA_ALG_IS_SIGN_HASH(alg) is true), that is compatible with the type of key.
 * @param hash              The input whose signature is to be verified. This is usually the hash of a message. See the
 *                          detailed description of this function and the description of individual signature
 *                          algorithms for a detailed description of acceptable inputs.
 * @param hash_length       Size of the hash buffer in bytes.
 * @param signature         Buffer containing the signature to verify.
 * @param signature_length  Size of the signature buffer in bytes.
 * @return psa_status_t
 *
 * PSA_SUCCESS                  The signature is valid.
 * PSA_ERROR_INVALID_HANDLE
 * PSA_ERROR_NOT_PERMITTED      The key does not have the PSA_KEY_USAGE_VERIFY_HASH flag, or it does not permit the
 *                              requested algorithm.
 * PSA_ERROR_INVALID_SIGNATURE  The calculation was performed successfully, but the passed signature
 *                              is not a valid signature.
 * PSA_ERROR_NOT_SUPPORTED
 * PSA_ERROR_INVALID_ARGUMENT
 * PSA_ERROR_INSUFFICIENT_MEMORY
 * PSA_ERROR_COMMUNICATION_FAILURE
 * PSA_ERROR_HARDWARE_FAILURE
 * PSA_ERROR_CORRUPTION_DETECTED
 * PSA_ERROR_STORAGE_FAILURE
 * PSA_ERROR_DATA_CORRUPT
 * PSA_ERROR_DATA_INVALID
 * PSA_ERROR_BAD_STATE          The library has not been previously initialized by psa_crypto_init(). It is
 *                              implementation-dependent whether a failure to initialize results in this error code.
 */
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
