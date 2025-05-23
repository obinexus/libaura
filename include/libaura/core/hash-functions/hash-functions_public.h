/**
 * @file hash-functions_public.h
 * @brief Public interface for LibAura hash functions
 * 
 * Implements hash functions with correctness, soundness, and hardness properties
 * for cryptographic operations and integrity verification.
 * 
 * Copyright © 2025 OBINexus Computing - Computing from the Heart
 */

#ifndef LIBAURA_HASH_FUNCTIONS_PUBLIC_H
#define LIBAURA_HASH_FUNCTIONS_PUBLIC_H

#include "hash-functions_types.h"
#include "hash-functions_constants.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize the hash functions module
 * @return 0 on success, non-zero on failure
 */
int libaura_hash_initialize(void);

/**
 * @brief Clean up the hash functions module
 */
void libaura_hash_cleanup(void);

/**
 * @brief Register hash function components with the container
 * @param registry_context Container registry context
 * @return 0 on success, non-zero on failure
 */
int libaura_hash_register_components(void* registry_context);

/**
 * @brief Initialize a hash context
 * @param context Hash context to initialize
 * @param digest_size Desired digest size
 * @return 0 on success, non-zero on failure
 */
int libaura_hash_init(libaura_hash_context_t* context, libaura_digest_size_t digest_size);

/**
 * @brief Update hash with data
 * @param context Hash context
 * @param data Input data buffer
 * @param size Size of input data
 * @return 0 on success, non-zero on failure
 */
int libaura_hash_update(libaura_hash_context_t* context, const void* data, size_t size);

/**
 * @brief Finalize hash and output digest
 * @param context Hash context
 * @param digest Output digest buffer
 * @return 0 on success, non-zero on failure
 */
int libaura_hash_final(libaura_hash_context_t* context, uint8_t* digest);

/**
 * @brief Compute hash digest in one operation
 * @param algorithm Hash algorithm identifier (LIBAURA_HASH_AURA64, etc.)
 * @param data Input data buffer
 * @param size Size of input data
 * @param digest Output digest buffer
 * @param digest_size Size of output buffer
 * @return 0 on success, non-zero on failure
 */
int libaura_hash_compute(int algorithm, const void* data, size_t size, 
                         uint8_t* digest, size_t digest_size);

/**
 * @brief Computes Aura64 hash
 * @param data Input data buffer
 * @param size Size of input data
 * @param digest Output digest buffer (must be at least 8 bytes)
 * @return 0 on success, non-zero on failure
 */
int libaura_hash_aura64(const void* data, size_t size, uint8_t digest[LIBAURA_DIGEST_SIZE_64]);

/**
 * @brief Computes Aura256 hash
 * @param data Input data buffer
 * @param size Size of input data
 * @param digest Output digest buffer (must be at least 32 bytes)
 * @return 0 on success, non-zero on failure
 */
int libaura_hash_aura256(const void* data, size_t size, uint8_t digest[LIBAURA_DIGEST_SIZE_256]);

/**
 * @brief Computes Aura512 hash
 * @param data Input data buffer
 * @param size Size of input data
 * @param digest Output digest buffer (must be at least 64 bytes)
 * @return 0 on success, non-zero on failure
 */
int libaura_hash_aura512(const void* data, size_t size, uint8_t digest[LIBAURA_DIGEST_SIZE_512]);

/**
 * @brief Verify hash against expected value with strict entropy checking
 * @param data Input data buffer
 * @param size Size of input data
 * @param expected_digest Expected digest to verify against
 * @param digest_size Size of digest
 * @return Hash verification result
 */
libaura_hash_result_t libaura_hash_verify(const void* data, size_t size,
                                         const uint8_t* expected_digest,
                                         size_t digest_size);

/**
 * @brief Check entropy distribution of data
 * @param data Data to analyze
 * @param size Size of data
 * @return Entropy distribution score (0-255, higher is more balanced)
 */
uint8_t libaura_hash_check_entropy(const void* data, size_t size);

/**
 * @brief Initialize HMAC context
 * @param context HMAC context to initialize
 * @param key Key material
 * @param key_length Length of key
 * @param digest_size Desired digest size
 * @return 0 on success, non-zero on failure
 */
int libaura_hmac_init(libaura_hmac_context_t* context, const uint8_t* key, 
                      size_t key_length, libaura_digest_size_t digest_size);

/**
 * @brief Update HMAC with data
 * @param context HMAC context
 * @param data Input data buffer
 * @param size Size of input data
 * @return 0 on success, non-zero on failure
 */
int libaura_hmac_update(libaura_hmac_context_t* context, const void* data, size_t size);

/**
 * @brief Finalize HMAC and output digest
 * @param context HMAC context
 * @param digest Output digest buffer
 * @return 0 on success, non-zero on failure
 */
int libaura_hmac_final(libaura_hmac_context_t* context, uint8_t* digest);

/**
 * @brief Compute HMAC in one operation
 * @param key Key material
 * @param key_length Length of key
 * @param data Input data buffer
 * @param size Size of input data
 * @param digest Output digest buffer
 * @param digest_size Desired digest size
 * @return 0 on success, non-zero on failure
 */
int libaura_hmac_compute(const uint8_t* key, size_t key_length,
                         const void* data, size_t size,
                         uint8_t* digest, size_t digest_size);

/**
 * @brief Derives a cryptographic key using HMAC following Kderived = HMACxA(yA) principle
 * @param private_key Private key (xA)
 * @param private_key_len Length of private key
 * @param public_key Public key (yA)
 * @param public_key_len Length of public key
 * @param derived_key Output buffer for derived key
 * @param key_size Size of the output buffer
 * @return 0 on success, non-zero on failure
 */
int libaura_hmac_derive_key(const uint8_t* private_key, size_t private_key_len,
                           const uint8_t* public_key, size_t public_key_len,
                           uint8_t* derived_key, size_t key_size);

/**
 * @brief Create an Aura ID file (.auraid)
 * @param identity_data Identity data buffer
 * @param identity_size Size of identity data
 * @param output_file Output file path
 * @return 0 on success, non-zero on failure
 */
int libaura_hash_create_id_file(const void* identity_data, size_t identity_size,
                               const char* output_file);

/**
 * @brief Create an Aura key file (.auraid.key)
 * @param identity_data Identity data buffer
 * @param identity_size Size of identity data
 * @param output_file Output file path
 * @return 0 on success, non-zero on failure
 */
int libaura_hash_create_key_file(const void* identity_data, size_t identity_size,
                                const char* output_file);

/**
 * @brief Verify an Aura ID file against identity data
 * @param id_file Path to .auraid file
 * @param key_file Path to .auraid.key file
 * @param identity_data Identity data buffer
 * @param identity_size Size of identity data
 * @return 0 on success, non-zero on failure
 */
int libaura_hash_verify_id(const char* id_file, const char* key_file,
                          const void* identity_data, size_t identity_size);

/**
 * @brief Get error message for hash result code
 * @param result Hash result code
 * @return Error message string
 */
const char* libaura_hash_get_error_message(libaura_hash_result_t result);

#ifdef __cplusplus
}
#endif

#endif /* LIBAURA_HASH_FUNCTIONS_PUBLIC_H */