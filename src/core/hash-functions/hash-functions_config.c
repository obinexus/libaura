/**
 * @file hash-functions_config.c
 * @brief Implementation of configuration system for hash functions
 * 
 * Provides functions for loading, saving, and manipulating hash function configuration.
 * 
 * Copyright © 2025 OBINexus Computing - Computing from the Heart
 */

#include "libaura/core/hash-functions/hash-functions_config.h"
#include "libaura/core/hash-functions/hash-functions_public.h"
#include "libaura/core/component-container/component-container_public.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

/* Default configuration values for each environment */
#define LIBAURA_DEFAULT_CONFIG_FILE "libaura_hash.config"
#define LIBAURA_DEFAULT_LOG_FILE "libaura_hash.log"

/* Default development configuration */
#define LIBAURA_DEV_DEFAULT_ALGORITHM LIBAURA_HASH_AURA64
#define LIBAURA_DEV_METADATA_ALGORITHM LIBAURA_HASH_AURA256
#define LIBAURA_DEV_KEY_DERIVATION_ALGORITHM LIBAURA_HASH_AURA256
#define LIBAURA_DEV_MIN_ENTROPY_AURA64 150
#define LIBAURA_DEV_MIN_ENTROPY_AURA256 180
#define LIBAURA_DEV_MIN_ENTROPY_AURA512 200
#define LIBAURA_DEV_ROUNDS_AURA64 6
#define LIBAURA_DEV_ROUNDS_AURA256 12
#define LIBAURA_DEV_ROUNDS_AURA512 18
#define LIBAURA_DEV_VERIFY_ENTROPY true
#define LIBAURA_DEV_ENABLE_TAMPER_DETECTION false
#define LIBAURA_DEV_ENABLE_LOGGING true

/* Default production configuration */
#define LIBAURA_PROD_DEFAULT_ALGORITHM LIBAURA_HASH_AURA512
#define LIBAURA_PROD_METADATA_ALGORITHM LIBAURA_HASH_AURA512
#define LIBAURA_PROD_KEY_DERIVATION_ALGORITHM LIBAURA_HASH_AURA512
#define LIBAURA_PROD_MIN_ENTROPY_AURA64 180
#define LIBAURA_PROD_MIN_ENTROPY_AURA256 210
#define LIBAURA_PROD_MIN_ENTROPY_AURA512 230
#define LIBAURA_PROD_ROUNDS_AURA64 8
#define LIBAURA_PROD_ROUNDS_AURA256 16
#define LIBAURA_PROD_ROUNDS_AURA512 24
#define LIBAURA_PROD_VERIFY_ENTROPY true
#define LIBAURA_PROD_ENABLE_TAMPER_DETECTION true
#define LIBAURA_PROD_ENABLE_LOGGING true

/* Configuration file constants */
#define LIBAURA_CONFIG_LINE_MAX 256
#define LIBAURA_CONFIG_VALUE_MAX 128
#define LIBAURA_CONFIG_COMMENT_CHAR '#'

/* Helper function to trim whitespace from a string */
static void trim_whitespace(char* str) {
    if (!str) {
        return;
    }
    
    /* Trim leading whitespace */
    char* start = str;
    while (*start && isspace((unsigned char)*start)) {
        start++;
    }
    
    /* All whitespace, return empty string */
    if (!*start) {
        *str = '\0';
        return;
    }
    
    /* Trim trailing whitespace */
    char* end = start + strlen(start) - 1;
    while (end > start && isspace((unsigned char)*end)) {
        end--;
    }
    
    /* Copy trimmed string back to original */
    if (start > str) {
        memmove(str, start, end - start + 1);
        str[end - start + 1] = '\0';
    } else {
        str[end - str + 1] = '\0';
    }
}

/* Helper function to copy a string with allocation */
static char* string_copy(const char* str) {
    if (!str) {
        return NULL;
    }
    
    char* copy = malloc(strlen(str) + 1);
    if (copy) {
        strcpy(copy, str);
    }
    
    return copy;
}

/* Initialize configuration with default values based on environment */
int libaura_hash_config_init(libaura_hash_config_t* config) {
    if (!config) {
        return -1;
    }
    
    /* Clear configuration structure */
    memset(config, 0, sizeof(libaura_hash_config_t));
    
    /* Default to development environment */
    config->environment = LIBAURA_ENV_DEVELOPMENT;
    
    /* Set defaults for development environment */
    config->default_algorithm = LIBAURA_DEV_DEFAULT_ALGORITHM;
    config->metadata_algorithm = LIBAURA_DEV_METADATA_ALGORITHM;
    config->key_derivation_algorithm = LIBAURA_DEV_KEY_DERIVATION_ALGORITHM;
    config->min_entropy_aura64 = LIBAURA_DEV_MIN_ENTROPY_AURA64;
    config->min_entropy_aura256 = LIBAURA_DEV_MIN_ENTROPY_AURA256;
    config->min_entropy_aura512 = LIBAURA_DEV_MIN_ENTROPY_AURA512;
    config->rounds_aura64 = LIBAURA_DEV_ROUNDS_AURA64;
    config->rounds_aura256 = LIBAURA_DEV_ROUNDS_AURA256;
    config->rounds_aura512 = LIBAURA_DEV_ROUNDS_AURA512;
    config->verify_entropy = LIBAURA_DEV_VERIFY_ENTROPY;
    config->enable_tamper_detection = LIBAURA_DEV_ENABLE_TAMPER_DETECTION;
    config->enable_logging = LIBAURA_DEV_ENABLE_LOGGING;
    
    /* Allocate strings */
    config->config_file = string_copy(LIBAURA_DEFAULT_CONFIG_FILE);
    config->log_file = string_copy(LIBAURA_DEFAULT_LOG_FILE);
    
    if (!config->config_file || !config->log_file) {
        libaura_hash_config_cleanup(config);
        return -1;
    }
    
    return 0;
}

/* Clean up configuration resources */
void libaura_hash_config_cleanup(libaura_hash_config_t* config) {
    if (!config) {
        return;
    }
    
    /* Free allocated strings */
    free(config->config_file);
    free(config->log_file);
    
    /* Reset to initial state */
    config->config_file = NULL;
    config->log_file = NULL;
}

/* Load configuration from file */
int libaura_hash_config_load(libaura_hash_config_t* config, const char* file_path) {
    if (!config || !file_path) {
        return -1;
    }
    
    /* Open configuration file */
    FILE* file = fopen(file_path, "r");
    if (!file) {
        return -1;
    }
    
    /* Initialize with defaults first */
    libaura_hash_config_init(config);
    
    /* Parse configuration file */
    char line[LIBAURA_CONFIG_LINE_MAX];
    while (fgets(line, sizeof(line), file) != NULL) {
        /* Skip comments and empty lines */
        if (line[0] == LIBAURA_CONFIG_COMMENT_CHAR || line[0] == '\n') {
            continue;
        }
        
        /* Find key-value separator */
        char* separator = strchr(line, '=');
        if (!separator) {
            continue;
        }
        
        /* Extract key and value */
        *separator = '\0';
        char* key = line;
        char* value = separator + 1;
        
        /* Trim whitespace */
        trim_whitespace(key);
        trim_whitespace(value);
        
        /* Set configuration value */
        libaura_hash_config_set(config, key, value);
    }
    
    fclose(file);
    
    /* Update config_file */
    free(config->config_file);
    config->config_file = string_copy(file_path);
    
    return 0;
}

/* Save configuration to file */
int libaura_hash_config_save(const libaura_hash_config_t* config, const char* file_path) {
    if (!config) {
        return -1;
    }
    
    /* Use provided file path or default to config_file */
    const char* output_path = file_path ? file_path : config->config_file;
    if (!output_path) {
        return -1;
    }
    
    /* Open configuration file */
    FILE* file = fopen(output_path, "w");
    if (!file) {
        return -1;
    }
    
    /* Write header */
    fprintf(file, "# LibAura Hash Functions Configuration\n");
    fprintf(file, "# Generated by LibAura v1.0.0\n");
    fprintf(file, "# Copyright © 2025 OBINexus Computing - Computing from the Heart\n\n");
    
    /* Write environment */
    const char* env_str = "development";
    switch (config->environment) {
        case LIBAURA_ENV_DEVELOPMENT:
            env_str = "development";
            break;
        case LIBAURA_ENV_TESTING:
            env_str = "testing";
            break;
        case LIBAURA_ENV_STAGING:
            env_str = "staging";
            break;
        case LIBAURA_ENV_PRODUCTION:
            env_str = "production";
            break;
    }
    fprintf(file, "environment=%s\n\n", env_str);
    
    /* Write algorithm configuration */
    fprintf(file, "# Algorithm Configuration\n");
    fprintf(file, "default_algorithm=%d\n", config->default_algorithm);
    fprintf(file, "metadata_algorithm=%d\n", config->metadata_algorithm);
    fprintf(file, "key_derivation_algorithm=%d\n\n", config->key_derivation_algorithm);
    
    /* Write entropy thresholds */
    fprintf(file, "# Entropy Configuration\n");
    fprintf(file, "min_entropy_aura64=%u\n", config->min_entropy_aura64);
    fprintf(file, "min_entropy_aura256=%u\n", config->min_entropy_aura256);
    fprintf(file, "min_entropy_aura512=%u\n\n", config->min_entropy_aura512);
    
    /* Write rounds configuration */
    fprintf(file, "# Transformation Rounds\n");
    fprintf(file, "rounds_aura64=%u\n", config->rounds_aura64);
    fprintf(file, "rounds_aura256=%u\n", config->rounds_aura256);
    fprintf(file, "rounds_aura512=%u\n\n", config->rounds_aura512);
    
    /* Write feature flags */
    fprintf(file, "# Features\n");
    fprintf(file, "verify_entropy=%s\n", config->verify_entropy ? "true" : "false");
    fprintf(file, "enable_tamper_detection=%s\n", config->enable_tamper_detection ? "true" : "false");
    fprintf(file, "enable_logging=%s\n\n", config->enable_logging ? "true" : "false");
    
    /* Write paths */
    fprintf(file, "# Paths\n");
    fprintf(file, "log_file=%s\n\n", config->log_file ? config->log_file : "");
    
    /* Write features */
    fprintf(file, "# Extension\n");
    fprintf(file, "features=0x%08X\n", config->features);
    
    fclose(file);
    
    return 0;
}

/* Set configuration value */
int libaura_hash_config_set(libaura_hash_config_t* config, const char* key, const char* value) {
    if (!config || !key || !value) {
        return -1;
    }
    
    /* Handle different configuration keys */
    if (strcmp(key, "environment") == 0) {
        if (strcmp(value, "development") == 0) {
            config->environment = LIBAURA_ENV_DEVELOPMENT;
        } else if (strcmp(value, "testing") == 0) {
            config->environment = LIBAURA_ENV_TESTING;
        } else if (strcmp(value, "staging") == 0) {
            config->environment = LIBAURA_ENV_STAGING;
        } else if (strcmp(value, "production") == 0) {
            config->environment = LIBAURA_ENV_PRODUCTION;
        }
    } else if (strcmp(key, "default_algorithm") == 0) {
        config->default_algorithm = atoi(value);
    } else if (strcmp(key, "metadata_algorithm") == 0) {
        config->metadata_algorithm = atoi(value);
    } else if (strcmp(key, "key_derivation_algorithm") == 0) {
        config->key_derivation_algorithm = atoi(value);
    } else if (strcmp(key, "min_entropy_aura64") == 0) {
        config->min_entropy_aura64 = (uint8_t)atoi(value);
    } else if (strcmp(key, "min_entropy_aura256") == 0) {
        config->min_entropy_aura256 = (uint8_t)atoi(value);
    } else if (strcmp(key, "min_entropy_aura512") == 0) {
        config->min_entropy_aura512 = (uint8_t)atoi(value);
    } else if (strcmp(key, "rounds_aura64") == 0) {
        config->rounds_aura64 = (uint8_t)atoi(value);
    } else if (strcmp(key, "rounds_aura256") == 0) {
        config->rounds_aura256 = (uint8_t)atoi(value);
    } else if (strcmp(key, "rounds_aura512") == 0) {
        config->rounds_aura512 = (uint8_t)atoi(value);
    } else if (strcmp(key, "verify_entropy") == 0) {
        config->verify_entropy = (strcmp(value, "true") == 0);
    } else if (strcmp(key, "enable_tamper_detection") == 0) {
        config->enable_tamper_detection = (strcmp(value, "true") == 0);
    } else if (strcmp(key, "enable_logging") == 0) {
        config->enable_logging = (strcmp(value, "true") == 0);
    } else if (strcmp(key, "log_file") == 0) {
        free(config->log_file);
        config->log_file = string_copy(value);
        if (!config->log_file) {
            return -1;
        }
    } else if (strcmp(key, "config_file") == 0) {
        free(config->config_file);
        config->config_file = string_copy(value);
        if (!config->config_file) {
            return -1;
        }
    } else if (strcmp(key, "features") == 0) {
        /* Parse hexadecimal or decimal feature flags */
        if (strncmp(value, "0x", 2) == 0) {
            sscanf(value, "0x%x", &config->features);
        } else {
            config->features = atoi(value);
        }
    } else {
        /* Unknown configuration key */
        return -1;
    }
    
    return 0;
}

/* Get configuration value */
int libaura_hash_config_get(const libaura_hash_config_t* config, const char* key, 
                          char* value, size_t value_size) {
    if (!config || !key || !value || value_size == 0) {
        return -1;
    }
    
    /* Handle different configuration keys */
    if (strcmp(key, "environment") == 0) {
        switch (config->environment) {
            case LIBAURA_ENV_DEVELOPMENT:
                snprintf(value, value_size, "development");
                break;
            case LIBAURA_ENV_TESTING:
                snprintf(value, value_size, "testing");
                break;
            case LIBAURA_ENV_STAGING:
                snprintf(value, value_size, "staging");
                break;
            case LIBAURA_ENV_PRODUCTION:
                snprintf(value, value_size, "production");
                break;
            default:
                snprintf(value, value_size, "unknown");
                break;
        }
    } else if (strcmp(key, "default_algorithm") == 0) {
        snprintf(value, value_size, "%d", config->default_algorithm);
    } else if (strcmp(key, "metadata_algorithm") == 0) {
        snprintf(value, value_size, "%d", config->metadata_algorithm);
    } else if (strcmp(key, "key_derivation_algorithm") == 0) {
        snprintf(value, value_size, "%d", config->key_derivation_algorithm);
    } else if (strcmp(key, "min_entropy_aura64") == 0) {
        snprintf(value, value_size, "%u", config->min_entropy_aura64);
    } else if (strcmp(key, "min_entropy_aura256") == 0) {
        snprintf(value, value_size, "%u", config->min_entropy_aura256);
    } else if (strcmp(key, "min_entropy_aura512") == 0) {
        snprintf(value, value_size, "%u", config->min_entropy_aura512);
    } else if (strcmp(key, "rounds_aura64") == 0) {
        snprintf(value, value_size, "%u", config->rounds_aura64);
    } else if (strcmp(key, "rounds_aura256") == 0) {
        snprintf(value, value_size, "%u", config->rounds_aura256);
    } else if (strcmp(key, "rounds_aura512") == 0) {
        snprintf(value, value_size, "%u", config->rounds_aura512);
    } else if (strcmp(key, "verify_entropy") == 0) {
        snprintf(value, value_size, "%s", config->verify_entropy ? "true" : "false");
    } else if (strcmp(key, "enable_tamper_detection") == 0) {
        snprintf(value, value_size, "%s", config->enable_tamper_detection ? "true" : "false");
    } else if (strcmp(key, "enable_logging") == 0) {
        snprintf(value, value_size, "%s", config->enable_logging ? "true" : "false");
    } else if (strcmp(key, "log_file") == 0) {
        snprintf(value, value_size, "%s", config->log_file ? config->log_file : "");
    } else if (strcmp(key, "config_file") == 0) {
        snprintf(value, value_size, "%s", config->config_file ? config->config_file : "");
    } else if (strcmp(key, "features") == 0) {
        snprintf(value, value_size, "0x%08X", config->features);
    } else {
        /* Unknown configuration key */
        value[0] = '\0';
        return -1;
    }
    
    return 0;
}

/* Create default configuration file */
int libaura_hash_config_create_default(const char* file_path, libaura_environment_t environment) {
    if (!file_path) {
        return -1;
    }
    
    /* Create default configuration */
    libaura_hash_config_t config;
    if (libaura_hash_config_init(&config) != 0) {
        return -1;
    }
    
    /* Update environment-specific settings */
    config.environment = environment;
    
    if (environment == LIBAURA_ENV_PRODUCTION) {
        /* Production defaults */
        config.default_algorithm = LIBAURA_PROD_DEFAULT_ALGORITHM;
        config.metadata_algorithm = LIBAURA_PROD_METADATA_ALGORITHM;
        config.key_derivation_algorithm = LIBAURA_PROD_KEY_DERIVATION_ALGORITHM;
        config.min_entropy_aura64 = LIBAURA_PROD_MIN_ENTROPY_AURA64;
        config.min_entropy_aura256 = LIBAURA_PROD_MIN_ENTROPY_AURA256;
        config.min_entropy_aura512 = LIBAURA_PROD_MIN_ENTROPY_AURA512;
        config.rounds_aura64 = LIBAURA_PROD_ROUNDS_AURA64;
        config.rounds_aura256 = LIBAURA_PROD_ROUNDS_AURA256;
        config.rounds_aura512 = LIBAURA_PROD_ROUNDS_AURA512;
        config.verify_entropy = LIBAURA_PROD_VERIFY_ENTROPY;
        config.enable_tamper_detection = LIBAURA_PROD_ENABLE_TAMPER_DETECTION;
        config.enable_logging = LIBAURA_PROD_ENABLE_LOGGING;
    }
    
    /* Save configuration to file */
    int result = libaura_hash_config_save(&config, file_path);
    
    /* Clean up */
    libaura_hash_config_cleanup(&config);
    
    return result;
}

/* Get default algorithm based on environment */
int libaura_hash_config_get_algorithm(const libaura_hash_config_t* config) {
    if (!config) {
        return LIBAURA_HASH_AURA256; /* Default fallback */
    }
    
    return config->default_algorithm;
}

/* Get entropy threshold for algorithm */
uint8_t libaura_hash_config_get_entropy_threshold(const libaura_hash_config_t* config, int algorithm) {
    if (!config) {
        return LIBAURA_MIN_ENTROPY_THRESHOLD; /* Default fallback */
    }
    
    switch (algorithm) {
        case LIBAURA_HASH_AURA64:
            return config->min_entropy_aura64;
        case LIBAURA_HASH_AURA256:
            return config->min_entropy_aura256;
        case LIBAURA_HASH_AURA512:
            return config->min_entropy_aura512;
        default:
            return LIBAURA_MIN_ENTROPY_THRESHOLD;
    }
}

/* Get rounds count for algorithm */
uint8_t libaura_hash_config_get_rounds(const libaura_hash_config_t* config, int algorithm) {
    if (!config) {
        /* Default fallbacks */
        switch (algorithm) {
            case LIBAURA_HASH_AURA64:
                return LIBAURA_ROUNDS_AURA64;
            case LIBAURA_HASH_AURA256:
                return LIBAURA_ROUNDS_AURA256;
            case LIBAURA_HASH_AURA512:
                return LIBAURA_ROUNDS_AURA512;
            default:
                return LIBAURA_ROUNDS_AURA256;
        }
    }
    
    switch (algorithm) {
        case LIBAURA_HASH_AURA64:
            return config->rounds_aura64;
        case LIBAURA_HASH_AURA256:
            return config->rounds_aura256;
        case LIBAURA_HASH_AURA512:
            return config->rounds_aura512;
        default:
            return config->rounds_aura256;
    }
}

/* Apply configuration to hash context */
int libaura_hash_config_apply(const libaura_hash_config_t* config, libaura_hash_context_t* context) {
    if (!config || !context) {
        return -1;
    }
    
    /* Set rounds based on digest size */
    switch (context->digest_size) {
        case LIBAURA_DIGEST_64:
            context->rounds = config->rounds_aura64;
            break;
        case LIBAURA_DIGEST_256:
            context->rounds = config->rounds_aura256;
            break;
        case LIBAURA_DIGEST_512:
            context->rounds = config->rounds_aura512;
            break;
        default:
            return -1;
    }
    
    return 0;
}

/* Register configuration with component container */
int libaura_hash_config_register(const libaura_hash_config_t* config, void* registry_context) {
    if (!config || !registry_context) {
        return -1;
    }
    
    libaura_container_context_t* context = (libaura_container_context_t*)registry_context;
    
    /* Create component interface for configuration */
    libaura_component_interface_t component = {
        .name = "libaura.hash.config",
        .create = NULL,  /* Configuration is stateless, no instance creation */
        .destroy = NULL,
        .get_interface = NULL,
        .verify = NULL,
        .hash = 0,       /* Will be calculated during registration */
        .entropy_distribution = 200  /* Default entropy distribution value */
    };
    
    /* Calculate component hash */
    uint8_t digest[32];
    if (libaura_hash_aura256(config, sizeof(*config), digest) != LIBAURA_HASH_SUCCESS) {
        return -1;
    }
    
    component.hash = ((uint32_t)digest[0] << 24) | ((uint32_t)digest[1] << 16) |
                    ((uint32_t)digest[2] << 8) | ((uint32_t)digest[3]);
    
    /* Register with container */
    return libaura_container_register_component(context, &component);
}