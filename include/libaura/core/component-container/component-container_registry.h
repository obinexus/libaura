/**
 * @file component-container_registry.h
 * @brief Component registry for IoC container
 * 
 * Implements a zero-knowledge component registry with cryptographic integrity
 * verification and HMAC-based derived keys as described in the formal proof.
 * 
 * Copyright © 2025 OBINexus Computing - Computing from the Heart
 */

#ifndef LIBAURA_COMPONENT_CONTAINER_REGISTRY_H
#define LIBAURA_COMPONENT_CONTAINER_REGISTRY_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Component interface for IoC container
 * Enforces correctness, soundness, and hardness principles
 */
typedef struct {
    const char* name;                /** Component unique identifier */
    void* (*create)(void);           /** Factory function to create component instance */
    void (*destroy)(void*);          /** Function to destroy component instance */
    void* (*get_interface)(void*);   /** Function to get component interface */
    int (*verify)(void*);            /** Self-verification function */
    uint32_t hash;                   /** Component integrity hash */
    uint8_t entropy_distribution;    /** Balance measure for hardness validation */
} libaura_component_interface_t;

/**
 * @brief Component registry for IoC container
 */
typedef struct {
    libaura_component_interface_t* components;  /** Array of registered components */
    size_t count;                               /** Number of registered components */
    size_t capacity;                            /** Capacity of components array */
    uint8_t integrity_check[32];                /** SHA-256 based integrity verification */
} libaura_component_registry_t;

/**
 * @brief Component verification context
 */
typedef struct {
    uint32_t component_hash;         /** Component hash for verification */
    uint8_t signature[64];           /** Cryptographic signature */
    uint64_t timestamp;              /** Creation timestamp */
    uint32_t permutation_mask;       /** Entropy-aware permutation mask */
} libaura_component_verify_context_t;

/**
 * @brief Initialize component registry
 * @param registry Registry to initialize
 * @param initial_capacity Initial component capacity
 * @return 0 on success, non-zero on failure
 */
int libaura_registry_init(libaura_component_registry_t* registry, size_t initial_capacity);

/**
 * @brief Clean up component registry
 * @param registry Registry to clean up
 */
void libaura_registry_cleanup(libaura_component_registry_t* registry);

/**
 * @brief Register a component
 * @param registry Target registry
 * @param component Component to register
 * @return 0 on success, non-zero on failure
 */
int libaura_registry_register(libaura_component_registry_t* registry, const libaura_component_interface_t* component);

/**
 * @brief Resolve a component by name
 * @param registry Source registry
 * @param name Component name to resolve
 * @return Component instance or NULL if not found
 */
void* libaura_registry_resolve(libaura_component_registry_t* registry, const char* name);

/**
 * @brief Verify registry integrity using HMAC-derived key
 * @param registry Registry to verify
 * @return 0 if integrity verification passes, non-zero otherwise
 */
int libaura_registry_verify(libaura_component_registry_t* registry);

/**
 * @brief Derives a cryptographic key using HMAC
 * Following Kderived = HMACxA(yA) principle from formal proof
 * @param private_key Private key (xA)
 * @param private_key_len Length of private key
 * @param public_key Public key (yA)
 * @param public_key_len Length of public key
 * @param derived_key Output buffer for derived key
 * @param key_size Size of the output buffer
 * @return 0 on success, non-zero on failure
 */
int libaura_derive_hmac_key(const uint8_t* private_key, size_t private_key_len,
                           const uint8_t* public_key, size_t public_key_len,
                           uint8_t* derived_key, size_t key_size);

/**
 * @brief Check entropy distribution of a component
 * @param data Component data to analyze
 * @param size Size of component data
 * @return Entropy distribution score (0-255, higher is more balanced)
 */
uint8_t libaura_check_entropy_distribution(const void* data, size_t size);

/**
 * @brief Save component registry state to file
 * @param registry Registry to save
 * @param filename File name for registry state
 * @return 0 on success, non-zero on failure
 */
int libaura_registry_save(const libaura_component_registry_t* registry, const char* filename);

/**
 * @brief Load component registry state from file
 * @param registry Registry to load into
 * @param filename File name for registry state
 * @return 0 on success, non-zero on failure
 */
int libaura_registry_load(libaura_component_registry_t* registry, const char* filename);

#ifdef __cplusplus
}
#endif

#endif /* LIBAURA_COMPONENT_CONTAINER_REGISTRY_H */