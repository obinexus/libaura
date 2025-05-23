/**
 * @file component-container_config.h
 * @brief Configuration interface for component container
 * 
 * Defines configuration structures and functions for the component container.
 * Implements the configuration aspects of the IoC container.
 * 
 * Copyright © 2025 OBINexus Computing - Computing from the Heart
 */

#ifndef LIBAURA_COMPONENT_CONTAINER_CONFIG_H
#define LIBAURA_COMPONENT_CONTAINER_CONFIG_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Security level for cryptographic operations
 */
typedef enum {
    LIBAURA_SECURITY_LOW,     /**< Lower security, higher performance */
    LIBAURA_SECURITY_MEDIUM,  /**< Balanced security and performance */
    LIBAURA_SECURITY_HIGH,    /**< Higher security, lower performance */
    LIBAURA_SECURITY_QUANTUM  /**< Quantum-resistant security */
} libaura_security_level_t;

/**
 * @brief Component container configuration
 */
typedef struct {
    size_t initial_capacity;            /**< Initial capacity for components */
    size_t max_components;              /**< Maximum number of components */
    libaura_security_level_t security;  /**< Security level */
    bool verify_on_resolve;             /**< Verify components on resolution */
    bool verify_entropy;                /**< Verify entropy distribution */
    bool allow_dynamic_loading;         /**< Allow loading components at runtime */
    char* log_file;                     /**< Log file path */
    char* config_file;                  /**< Configuration file path */
    uint32_t features;                  /**< Feature flags */
} libaura_container_config_t;

/**
 * @brief Initialize container configuration with defaults
 * @param config Configuration to initialize
 * @return 0 on success, non-zero on failure
 */
int libaura_config_init(libaura_container_config_t* config);

/**
 * @brief Clean up container configuration
 * @param config Configuration to clean up
 */
void libaura_config_cleanup(libaura_container_config_t* config);

/**
 * @brief Load container configuration from file
 * @param config Configuration to load into
 * @param file_path Configuration file path
 * @return 0 on success, non-zero on failure
 */
int libaura_config_load(libaura_container_config_t* config, const char* file_path);

/**
 * @brief Save container configuration to file
 * @param config Configuration to save
 * @param file_path Configuration file path
 * @return 0 on success, non-zero on failure
 */
int libaura_config_save(const libaura_container_config_t* config, const char* file_path);

/**
 * @brief Set configuration value
 * @param config Configuration to update
 * @param key Configuration key
 * @param value Configuration value
 * @return 0 on success, non-zero on failure
 */
int libaura_config_set(libaura_container_config_t* config, const char* key, const char* value);

/**
 * @brief Get configuration value
 * @param config Configuration to query
 * @param key Configuration key
 * @param value Buffer to store value
 * @param value_size Size of value buffer
 * @return 0 on success, non-zero on failure
 */
int libaura_config_get(const libaura_container_config_t* config, const char* key, 
                     char* value, size_t value_size);

/**
 * @brief Create default configuration file
 * @param file_path Configuration file path
 * @return 0 on success, non-zero on failure
 */
int libaura_config_create_default(const char* file_path);

#ifdef __cplusplus
}
#endif

#endif /* LIBAURA_COMPONENT_CONTAINER_CONFIG_H */