/**
 * @file component-container_public.h
 * @brief Public interface for component container
 * 
 * Implements the Phantom Encoder pattern for zero-knowledge component registration
 * and resolution with cryptographic integrity verification.
 * 
 * Copyright © 2025 OBINexus Computing - Computing from the Heart
 */

#ifndef LIBAURA_COMPONENT_CONTAINER_PUBLIC_H
#define LIBAURA_COMPONENT_CONTAINER_PUBLIC_H

#include "libaura/core/component-container/component-container_registry.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Component container context
 */
typedef struct libaura_container_context libaura_container_context_t;

/**
 * @brief Component descriptor
 */
typedef struct {
    const char* name;                /** Component name */
    const char* version;             /** Component version */
    uint32_t features;               /** Feature flags */
    uint8_t id[32];                  /** Identity hash */
    uint8_t key[64];                 /** Verification key */
} libaura_component_descriptor_t;

/**
 * @brief Create a new component container
 * @param initial_capacity Initial capacity for components
 * @return New container context or NULL on failure
 */
libaura_container_context_t* libaura_container_create(size_t initial_capacity);

/**
 * @brief Destroy a component container
 * @param context Container context to destroy
 */
void libaura_container_destroy(libaura_container_context_t* context);

/**
 * @brief Register a component with the container
 * @param context Container context
 * @param component Component interface
 * @return 0 on success, non-zero on failure
 */
int libaura_container_register_component(libaura_container_context_t* context, 
                                       const libaura_component_interface_t* component);

/**
 * @brief Resolve a component by name
 * @param context Container context
 * @param name Component name
 * @return Component instance or NULL if not found
 */
void* libaura_container_resolve(libaura_container_context_t* context, const char* name);

/**
 * @brief Get the registry from a container
 * @param context Container context
 * @return Registry or NULL on failure
 */
const libaura_component_registry_t* libaura_container_get_registry(const libaura_container_context_t* context);

/**
 * @brief Create a component challenge for zero-knowledge verification
 * @param context Container context
 * @param component_name Component name
 * @param challenge Output buffer for challenge
 * @param challenge_size Size of challenge buffer
 * @return 0 on success, non-zero on failure
 */
int libaura_container_create_challenge(const libaura_container_context_t* context,
                                     const char* component_name,
                                     uint8_t* challenge,
                                     size_t challenge_size);

/**
 * @brief Verify a component response to a challenge
 * @param context Container context
 * @param component_name Component name
 * @param challenge Challenge that was issued
 * @param challenge_size Size of challenge
 * @param response Response to verify
 * @param response_size Size of response
 * @return 0 on success, non-zero on failure
 */
int libaura_container_verify_response(const libaura_container_context_t* context,
                                    const char* component_name,
                                    const uint8_t* challenge,
                                    size_t challenge_size,
                                    const uint8_t* response,
                                    size_t response_size);

/**
 * @brief Create a component descriptor file (.aura.id)
 * @param component_name Component name
 * @param version Component version
 * @param features Feature flags
 * @param output_file Output file path
 * @return 0 on success, non-zero on failure
 */
int libaura_container_create_descriptor(const char* component_name,
                                      const char* version,
                                      uint32_t features,
                                      const char* output_file);

/**
 * @brief Create a component verification key file (.aura.id.key)
 * @param component_name Component name
 * @param version Component version
 * @param features Feature flags
 * @param output_file Output file path
 * @return 0 on success, non-zero on failure
 */
int libaura_container_create_key(const char* component_name,
                               const char* version,
                               uint32_t features,
                               const char* output_file);

/**
 * @brief Load a component descriptor from file
 * @param file_path Path to .aura.id file
 * @param descriptor Output descriptor
 * @return 0 on success, non-zero on failure
 */
int libaura_container_load_descriptor(const char* file_path,
                                    libaura_component_descriptor_t* descriptor);

/**
 * @brief Load a component verification key from file
 * @param file_path Path to .aura.id.key file
 * @param descriptor Descriptor to update with key
 * @return 0 on success, non-zero on failure
 */
int libaura_container_load_key(const char* file_path,
                             libaura_component_descriptor_t* descriptor);

/**
 * @brief Derives a purpose-specific component ID
 * @param context Container context
 * @param base_component Component name
 * @param purpose Purpose string (e.g., "authentication")
 * @param derived_id Output buffer for derived ID
 * @param derived_id_size Size of derived ID buffer
 * @return 0 on success, non-zero on failure
 */
int libaura_container_derive_id(const libaura_container_context_t* context,
                              const char* base_component,
                              const char* purpose,
                              uint8_t* derived_id,
                              size_t derived_id_size);

#ifdef __cplusplus
}
#endif

#endif /* LIBAURA_COMPONENT_CONTAINER_PUBLIC_H */