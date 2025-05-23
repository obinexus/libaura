/**
 * @file hash-functions_constants.h
 * @brief Constants for LibAura hash functions
 * 
 * Defines constants, magic values, and configuration parameters
 * for the hash function implementation.
 * 
 * Copyright © 2025 OBINexus Computing - Computing from the Heart
 */

#ifndef LIBAURA_HASH_FUNCTIONS_CONSTANTS_H
#define LIBAURA_HASH_FUNCTIONS_CONSTANTS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Hash algorithm identifiers
 */
#define LIBAURA_HASH_AURA64      0x01
#define LIBAURA_HASH_AURA256     0x02
#define LIBAURA_HASH_AURA512     0x03

/**
 * @brief Digest size constants (in bytes)
 */
#define LIBAURA_DIGEST_SIZE_64    8
#define LIBAURA_DIGEST_SIZE_256  32
#define LIBAURA_DIGEST_SIZE_512  64

/**
 * @brief Transformation round counts
 */
#define LIBAURA_ROUNDS_AURA64    8
#define LIBAURA_ROUNDS_AURA256  16
#define LIBAURA_ROUNDS_AURA512  24

/**
 * @brief Block size for hash functions (in bytes)
 */
#define LIBAURA_BLOCK_SIZE      64

/**
 * @brief Entropy thresholds for validation
 */
#define LIBAURA_MIN_ENTROPY_THRESHOLD   180  /**< Minimum acceptable entropy (0-255) */
#define LIBAURA_OPTIMAL_ENTROPY_THRESHOLD 220 /**< Optimal entropy distribution */

/**
 * @brief Magic constants for the hash function
 * These values ensure balanced entropy distribution
 */
static const uint64_t LIBAURA_HASH_MAGIC[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

/**
 * @brief Component registry identifiers
 */
#define LIBAURA_HASH_COMPONENT_AURA64   "libaura.hash.aura64"
#define LIBAURA_HASH_COMPONENT_AURA256  "libaura.hash.aura256"
#define LIBAURA_HASH_COMPONENT_AURA512  "libaura.hash.aura512"
#define LIBAURA_HMAC_COMPONENT          "libaura.hash.hmac"

/**
 * @brief Error codes
 */
#define LIBAURA_HASH_SUCCESS             0
#define LIBAURA_HASH_ERROR_INVALID_PARAM -1
#define LIBAURA_HASH_ERROR_MEMORY        -2
#define LIBAURA_HASH_ERROR_ENTROPY       -3
#define LIBAURA_HASH_ERROR_COMPONENT     -4
#define LIBAURA_HASH_ERROR_TAMPERED      -5

#ifdef __cplusplus
}
#endif

#endif /* LIBAURA_HASH_FUNCTIONS_CONSTANTS_H */