/**
 * @file hash-functions_config.h
 * @brief Configuration interface for LibAura hash functions
 * 
 * Provides inversion of control (IoC) for hash function configuration,
 * allowing runtime selection of hash function parameters and algorithm variants.
 * 
 * Copyright © 2025 OBINexus Computing - Computing from the Heart
 */

#ifndef LIBAURA_HASH_FUNCTIONS_CONFIG_H
#define LIBAURA_HASH_FUNCTIONS_CONFIG_H

#include "hash-functions_types.h"
#include "hash-functions_constants.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Runtime environment types
 */
typedef enum {
    LIBAURA_ENV_DEVELOPMENT = 0,  /**< Development environment (lower security) */
    LIBAURA_ENV_TESTING = 1,      /**< Testing environment */
    LIBAURA_ENV_STAGING = 2,      /**< Staging environment */
    LIBAURA_ENV_PRODUCTION = 3    /**< Production environment (highest security) */
} libaura_environment_t;

/**
 * @brief Hash function configuration structure
 */
typedef struct {
    /* General configuration */
    char* config_file;              /**< Configuration file path */
    libaura_environment_t environment; /**< Runtime environment */
    bool verify_entropy;            /**< Enable entropy verification */
    bool enable_tamper_detection;   /**< Enable enhanced tamper detection */
    
    /* Algorithm selection */
    int default_algorithm;          /**< Default algorithm when not specified */
    int metadata_algorithm;         /**< Algorithm for metadata hashing */
    int key_derivation_algorithm;   /**< Algorithm for key derivation */
    
    /* Entropy thresholds */
    uint8_t min_entropy_aura64;     /**< Minimum entropy for Aura64 */
    uint8_t min_entropy_aura256;    /**< Minimum entropy for Aura256 */
    uint8_t min_entropy_aura512;    /**< Minimum entropy for Aura512 */
    
    /* Performance configuration */
    uint8_t rounds_aura64;          /**< Transformation rounds for Aura64 */
    uint8_t rounds_aura256;         /**< Transformation rounds for Aura256 */
    uint8_t rounds_aura512;         /**< Transformation rounds for Aura512 */
    
    /* Extra features */
    bool enable_logging;            /**< Enable operation logging */
    char* log_file;                 /**< Log file path */
    uint32_t features;              /**< Feature flags for future extensions */
} libaura_hash_config_t;

/**
 * @brief Initialize configuration with default values
 * @param config Configuration structure to initialize
 * @return 0 on success, non-zero on failure
 */
int libaura_hash_config_init(libaura_hash_config_t* config);

/**
 * @brief Clean up configuration resources
 * @param config Configuration structure to clean up
 */
void libaura_hash_config_cleanup(libaura_hash_config_t* config);

/**
 * @brief Load configuration from file
 * @param config Configuration structure to load into
 * @param file_path Configuration file path
 * @return 0 on success, non-zero on failure
 */
int libaura_hash_config_load(libaura_hash_config_t* config, const char* file_path);

/**
 * @brief Save configuration to file
 * @param config Configuration structure to save
 * @param file_path Configuration file path (or NULL to use config->config_file)
 * @return 0 on success, non-zero on failure
 */
int libaura_hash_config_save(const libaura_hash_config_t* config, const char* file_path);

/**
 * @brief Set configuration value
 * @param config Configuration structure
 * @param key Configuration key
 * @param value Configuration value
 * @return 0 on success, non-zero on failure
 */
int libaura_hash_config_set(libaura_hash_config_t* config, const char* key, const char* value);

/**
 * @brief Get configuration value
 * @param config Configuration structure
 * @param key Configuration key
 * @param value Output buffer for value
 * @param value_size Size of output buffer
 * @return 0 on success, non-zero on failure
 */
int libaura_hash_config_get(const libaura_hash_config_t* config, const char* key, 
                         char* value, size_t value_size);

/**
 * @brief Create default configuration file
 * @param file_path Output file path
 * @param environment Target environment
 * @return 0 on success, non-zero on failure
 */
int libaura_hash_config_create_default(const char* file_path, libaura_environment_t environment);

/**
 * @brief Get default algorithm based on environment
 * @param config Configuration structure
 * @return Algorithm identifier (LIBAURA_HASH_AURA64, etc.)
 */
int libaura_hash_config_get_algorithm(const libaura_hash_config_t* config);

/**
 * @brief Get entropy threshold for algorithm
 * @param config Configuration structure
 * @param algorithm Algorithm identifier
 * @return Entropy threshold (0-255)
 */
uint8_t libaura_hash_config_get_entropy_threshold(const libaura_hash_config_t* config, int algorithm);

/**
 * @brief Get rounds count for algorithm
 * @param config Configuration structure
 * @param algorithm Algorithm identifier
 * @return Number of transformation rounds
 */
uint8_t libaura_hash_config_get_rounds(const libaura_hash_config_t* config, int algorithm);

/**
 * @brief Apply configuration to hash context
 * @param config Configuration structure
 * @param context Hash context to configure
 * @return 0 on success, non-zero on failure
 */
int libaura_hash_config_apply(const libaura_hash_config_t* config, libaura_hash_context_t* context);

/**
 * @brief Register configuration with component container
 * @param config Configuration structure
 * @param registry_context Component registry context
 * @return 0 on success, non-zero on failure
 */
int libaura_hash_config_register(const libaura_hash_config_t* config, void* registry_context);

#ifdef __cplusplus
}
#endif

#endif /* LIBAURA_HASH_FUNCTIONS_CONFIG_H */