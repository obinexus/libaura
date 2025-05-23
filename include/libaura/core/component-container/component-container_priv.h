/**
 * @file component-container_priv.h
 * @brief Private interface for component container
 * 
 * Contains internal functions and data structures not exposed to public API.
 * Implements the zero-knowledge principles from the formal proof document.
 * 
 * Copyright © 2025 OBINexus Computing - Computing from the Heart
 */

#ifndef LIBAURA_COMPONENT_CONTAINER_PRIV_H
#define LIBAURA_COMPONENT_CONTAINER_PRIV_H

#include "libaura/core/component-container/component-container_registry.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/**
 * @brief Internal container state
 */
typedef struct {
    uint32_t transaction_id;
    uint64_t timestamp;
    uint8_t state_hash[32];
    uint8_t last_operation_hash[32];
} libaura_container_state_t;

/**
 * @brief Verify a component's integrity
 * @param component Component to verify
 * @param size Size of component structure
 * @param expected_hash Expected hash value
 * @return 0 if verification passes, non-zero otherwise
 */
int libaura_verify_component(const void* component, size_t size, uint32_t expected_hash);

/**
 * @brief Generate a cryptographically secure random challenge
 * @param challenge Buffer to store challenge
 * @param challenge_size Size of challenge buffer
 * @return 0 on success, non-zero on failure
 */
int libaura_generate_challenge(uint8_t* challenge, size_t challenge_size);

/**
 * @brief Create a zero-knowledge proof for a component
 * @param component_hash Component hash
 * @param private_key Private key for signing
 * @param private_key_size Size of private key
 * @param challenge Challenge to respond to
 * @param challenge_size Size of challenge
 * @param proof Output buffer for proof
 * @param proof_size Size of proof buffer
 * @return 0 on success, non-zero on failure
 */
int libaura_create_zkp(uint32_t component_hash,
                     const uint8_t* private_key, size_t private_key_size,
                     const uint8_t* challenge, size_t challenge_size,
                     uint8_t* proof, size_t* proof_size);

/**
 * @brief Verify a zero-knowledge proof
 * @param component_hash Component hash
 * @param public_key Public key for verification
 * @param public_key_size Size of public key
 * @param challenge Challenge that was issued
 * @param challenge_size Size of challenge
 * @param proof Proof to verify
 * @param proof_size Size of proof
 * @return 0 if proof is valid, non-zero otherwise
 */
int libaura_verify_zkp(uint32_t component_hash,
                     const uint8_t* public_key, size_t public_key_size,
                     const uint8_t* challenge, size_t challenge_size,
                     const uint8_t* proof, size_t proof_size);

/**
 * @brief Update the component container state
 * @param state Container state to update
 * @param operation_desc Description of operation
 * @param operation_data Operation data
 * @param operation_size Size of operation data
 * @return 0 on success, non-zero on failure
 */
int libaura_update_container_state(libaura_container_state_t* state,
                                 const char* operation_desc,
                                 const void* operation_data,
                                 size_t operation_size);

/**
 * @brief Generate a component hash for verification
 * @param component Component data to hash
 * @param size Size of component data
 * @return Component hash
 */
uint32_t libaura_generate_component_hash(const void* component, size_t size);

/**
 * @brief Combine multiple components into a single verification chain
 * @param components Array of component hashes
 * @param count Number of components
 * @param chain_hash Output buffer for chain hash
 * @return 0 on success, non-zero on failure
 */
int libaura_combine_component_chain(const uint32_t* components, size_t count, uint8_t* chain_hash);

/**
 * @brief Verify a component dependency chain
 * @param chain_hash Chain hash to verify
 * @param components Array of component hashes
 * @param count Number of components
 * @return 0 if verification passes, non-zero otherwise
 */
int libaura_verify_component_chain(const uint8_t* chain_hash, const uint32_t* components, size_t count);

#endif /* LIBAURA_COMPONENT_CONTAINER_PRIV_H */