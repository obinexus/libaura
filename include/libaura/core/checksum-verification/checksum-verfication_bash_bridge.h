/**
 * @file checksum-verification_hash_bridge.h
 * @brief Integration interface between hash-functions and checksum-verification modules
 * 
 * Provides public API for using hash-functions capabilities within
 * the checksum-verification system.
 * 
 * Copyright © 2025 OBINexus Computing - Computing from the Heart
 */

#ifndef LIBAURA_CHECKSUM_VERIFICATION_HASH_BRIDGE_H
#define LIBAURA_CHECKSUM_VERIFICATION_HASH_BRIDGE_H

#include "libaura/core/checksum-verification/checksum-verification_public.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize hash functions for checksum verification
 * @return 0 on success, non-zero on failure
 */
int libaura_checksum_hash_initialize(void);

/**
 * @brief Clean up hash functions for checksum verification
 */
void libaura_checksum_hash_cleanup(void);

/**
 * @brief Create verification context using hash functions
 * @param options Checksum verification options
 * @return Verification context or NULL on failure
 */
void* libaura_checksum_hash_create_context(const libaura_checksum_options_t* options);

/**
 * @brief Destroy verification context created with hash functions
 * @param ctx Verification context
 */
void libaura_checksum_hash_destroy_context(void* ctx);

/**
 * @brief Update verification context with data using hash functions
 * @param ctx Verification context
 * @param data Data to update with
 * @param size Size of data
 * @return 0 on success, non-zero on failure
 */
int libaura_checksum_hash_update(void* ctx, const void* data, size_t size);

/**
 * @brief Finalize verification and get checksum using hash functions
 * @param ctx Verification context
 * @param checksum Output buffer for checksum
 * @param size Size of output buffer
 * @return 0 on success, non-zero on failure
 */
int libaura_checksum_hash_finalize(void* ctx, uint8_t* checksum, size_t size);

/**
 * @brief Verify checksum against data using hash functions
 * @param options Verification options
 * @param data Data to verify
 * @param size Size of data
 * @param expected_checksum Expected checksum
 * @param checksum_size Size of expected checksum
 * @return Verification result
 */
libaura_checksum_result_t libaura_checksum_hash_verify(
    const libaura_checksum_options_t* options,
    const void* data,
    size_t size,
    const uint8_t* expected_checksum,
    size_t checksum_size);

/**
 * @brief Verify HMAC derived key using hash functions
 * @param options Verification options
 * @param private_key Private key
 * @param private_key_len Private key length
 * @param public_key Public key
 * @param public_key_len Public key length
 * @param expected_key Expected derived key
 * @param key_size Size of expected key
 * @return Verification result
 */
libaura_checksum_result_t libaura_checksum_hash_verify_hmac_key(
    const libaura_checksum_options_t* options,
    const uint8_t* private_key,
    size_t private_key_len,
    const uint8_t* public_key,
    size_t public_key_len,
    const uint8_t* expected_key,
    size_t key_size);

/**
 * @brief Register checksum hash verification functions with the component container
 * @param container_context Component container context
 * @return 0 on success, non-zero on failure
 */
int libaura_checksum_hash_register(void* container_context);

#ifdef __cplusplus
}
#endif

#endif /* LIBAURA_CHECKSUM_VERIFICATION_HASH_BRIDGE_H */