/**
 * @file hash-functions_types.h
 * @brief Type definitions for LibAura hash functions
 * 
 * Defines types used for hash function operations, ensuring compatibility
 * with the component container system and registry.
 * 
 * Copyright © 2025 OBINexus Computing - Computing from the Heart
 */

#ifndef LIBAURA_HASH_FUNCTIONS_TYPES_H
#define LIBAURA_HASH_FUNCTIONS_TYPES_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Digest size enumeration
 */
typedef enum {
    LIBAURA_DIGEST_64 = 0,   /**< 64-bit digest (8 bytes) */
    LIBAURA_DIGEST_256 = 1,  /**< 256-bit digest (32 bytes) */
    LIBAURA_DIGEST_512 = 2   /**< 512-bit digest (64 bytes) */
} libaura_digest_size_t;

/**
 * @brief Hash function context for incremental hashing
 */
typedef struct {
    uint8_t state[64];       /**< Internal state buffer */
    uint64_t processed_bytes; /**< Count of bytes processed */
    uint8_t buffer[128];     /**< Input buffer for partial blocks */
    size_t buffer_size;      /**< Number of bytes in buffer */
    libaura_digest_size_t digest_size; /**< Output digest size */
    uint8_t rounds;          /**< Number of transformation rounds */
    uint8_t entropy_map[256]; /**< Entropy distribution tracking */
} libaura_hash_context_t;

/**
 * @brief HMAC context for key derivation
 */
typedef struct {
    libaura_hash_context_t hash_ctx; /**< Hash context for HMAC */
    uint8_t key[128];        /**< HMAC key material */
    size_t key_length;       /**< Length of HMAC key */
    bool initialized;        /**< Initialization status */
} libaura_hmac_context_t;

/**
 * @brief Hash verification result
 */
typedef enum {
    LIBAURA_HASH_VALID = 0,            /**< Hash verification successful */
    LIBAURA_HASH_INVALID = -1,         /**< Hash mismatch */
    LIBAURA_HASH_ERROR = -2,           /**< Error during verification */
    LIBAURA_HASH_ENTROPY_LOW = -3,     /**< Insufficient entropy distribution */
    LIBAURA_HASH_TAMPERED = -4         /**< Evidence of tampering detected */
} libaura_hash_result_t;

/**
 * @brief Hash component interface for registry
 */
typedef struct {
    const char* name;                /**< Hash algorithm name */
    libaura_digest_size_t digest_size; /**< Output digest size */
    uint8_t min_entropy;             /**< Minimum acceptable entropy score */
    uint8_t security_level;          /**< Security level (1-5) */
    const char* description;         /**< Algorithm description */
} libaura_hash_info_t;

#ifdef __cplusplus
}
#endif

#endif /* LIBAURA_HASH_FUNCTIONS_TYPES_H */