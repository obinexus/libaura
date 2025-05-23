/**
 * @file component-container_verify.h
 * @brief Verification interface for component container
 * 
 * Implements the zero-knowledge verification system for components.
 * Uses the formal proof principles for secure verification.
 * 
 * Copyright © 2025 OBINexus Computing - Computing from the Heart
 */

#ifndef LIBAURA_COMPONENT_CONTAINER_VERIFY_H
#define LIBAURA_COMPONENT_CONTAINER_VERIFY_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Verification context for components
 */
typedef struct libaura_verify_context libaura_verify_context_t;

/**
 * @brief Verification result codes
 */
typedef enum {
    LIBAURA_VERIFY_SUCCESS = 0,            /**< Verification succeeded */
    LIBAURA_VERIFY_FAILED = -1,            /**< Verification failed */
    LIBAURA_VERIFY_ERROR = -2,             /**< Error during verification */
    LIBAURA_VERIFY_TAMPERED = -3,          /**< Component has been tampered with */
    LIBAURA_VERIFY_EXPIRED = -4,           /**< Component has expired */
    LIBAURA_VERIFY_CHALLENGE_FAILED = -5,  /**< Challenge-response verification failed */
    LIBAURA_VERIFY_PROOF_INVALID = -6,     /**< Zero-knowledge proof is invalid */
    LIBAURA_VERIFY_ENTROPY_LOW = -7        /**< Entropy distribution check failed */
} libaura_verify_result_t;

/**
 * @brief Create verification context
 * @return New verification context or NULL on failure
 */
libaura_verify_context_t* libaura_verify_create_context(void);

/**
 * @brief Destroy verification context
 * @param context Verification context to destroy
 */
void libaura_verify_destroy_context(libaura_verify_context_t* context);

/**
 * @brief Verify a component
 * @param context Verification context
 * @param component Component data
 * @param size Size of component data
 * @param expected_hash Expected hash value
 * @return Verification result
 */
libaura_verify_result_t libaura_verify_component_data(libaura_verify_context_t* context,
                                                const void* component,
                                                size_t size,
                                                uint32_t expected_hash);

/**
 * @brief Generate verification challenge
 * @param context Verification context
 * @param challenge Output buffer for challenge
 * @param challenge_size Size of challenge buffer
 * @return 0 on success, non-zero on failure
 */
int libaura_verify_generate_challenge(libaura_verify_context_t* context,
                                    uint8_t* challenge,
                                    size_t challenge_size);

/**
 * @brief Verify challenge response
 * @param context Verification context
 * @param challenge Challenge that was issued
 * @param challenge_size Size of challenge
 * @param response Response to verify
 * @param response_size Size of response
 * @param public_key Public key for verification
 * @param public_key_size Size of public key
 * @return Verification result
 */
libaura_verify_result_t libaura_verify_challenge_response(libaura_verify_context_t* context,
                                                    const uint8_t* challenge,
                                                    size_t challenge_size,
                                                    const uint8_t* response,
                                                    size_t response_size,
                                                    const uint8_t* public_key,
                                                    size_t public_key_size);

/**
 * @brief Create zero-knowledge proof
 * @param context Verification context
 * @param private_key Private key for proof generation
 * @param private_key_size Size of private key
 * @param challenge Challenge to respond to
 * @param challenge_size Size of challenge
 * @param proof Output buffer for proof
 * @param proof_size Size of proof buffer (in/out)
 * @return 0 on success, non-zero on failure
 */
int libaura_verify_create_proof(libaura_verify_context_t* context,
                              const uint8_t* private_key,
                              size_t private_key_size,
                              const uint8_t* challenge,
                              size_t challenge_size,
                              uint8_t* proof,
                              size_t* proof_size);

/**
 * @brief Verify zero-knowledge proof
 * @param context Verification context
 * @param public_key Public key for verification
 * @param public_key_size Size of public key
 * @param challenge Challenge that was issued
 * @param challenge_size Size of challenge
 * @param proof Proof to verify
 * @param proof_size Size of proof
 * @return Verification result
 */
libaura_verify_result_t libaura_verify_proof(libaura_verify_context_t* context,
                                       const uint8_t* public_key,
                                       size_t public_key_size,
                                       const uint8_t* challenge,
                                       size_t challenge_size,
                                       const uint8_t* proof,
                                       size_t proof_size);

/**
 * @brief Check entropy distribution
 * @param context Verification context
 * @param data Data to analyze
 * @param size Size of data
 * @param min_entropy Minimum acceptable entropy (0-255)
 * @return Verification result
 */
libaura_verify_result_t libaura_verify_entropy(libaura_verify_context_t* context,
                                         const void* data,
                                         size_t size,
                                         uint8_t min_entropy);

/**
 * @brief Get entropy score
 * @param context Verification context
 * @param data Data to analyze
 * @param size Size of data
 * @return Entropy score (0-255) or negative value on error
 */
int libaura_verify_get_entropy_score(libaura_verify_context_t* context,
                                   const void* data,
                                   size_t size);

/**
 * @brief Get error message for verification result
 * @param result Verification result
 * @return Error message string
 */
const char* libaura_verify_get_error_message(libaura_verify_result_t result);

#ifdef __cplusplus
}
#endif

#endif /* LIBAURA_COMPONENT_CONTAINER_VERIFY_H */