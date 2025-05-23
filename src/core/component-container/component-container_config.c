/**
 * @file component-container_config.c
 * @brief Implementation of configuration system for component container
 * 
 * Provides functions for loading, saving, and manipulating container configuration.
 * 
 * Copyright © 2025 OBINexus Computing - Computing from the Heart
 */

#include "libaura/core/component-container/component-container_config.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

/* Default configuration values */
#define LIBAURA_DEFAULT_INITIAL_CAPACITY 32
#define LIBAURA_DEFAULT_MAX_COMPONENTS 1024
#define LIBAURA_DEFAULT_SECURITY LIBAURA_SECURITY_MEDIUM
#define LIBAURA_DEFAULT_VERIFY_ON_RESOLVE true
#define LIBAURA_DEFAULT_VERIFY_ENTROPY true
#define LIBAURA_DEFAULT_ALLOW_DYNAMIC_LOADING false
#define LIBAURA_DEFAULT_LOG_FILE "libaura.log"
#define LIBAURA_DEFAULT_CONFIG_FILE "libaura.config"
#define LIBAURA_DEFAULT_FEATURES 0

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

int libaura_config_init(libaura_container_config_t* config) {
    if (!config) {
        return -1;
    }
    
    /* Set default values */
    config->initial_capacity = LIBAURA_DEFAULT_INITIAL_CAPACITY;
    config->max_components = LIBAURA_DEFAULT_MAX_COMPONENTS;
    config->security = LIBAURA_DEFAULT_SECURITY;
    config->verify_on_resolve = LIBAURA_DEFAULT_VERIFY_ON_RESOLVE;
    config->verify_entropy = LIBAURA_DEFAULT_VERIFY_ENTROPY;
    config->allow_dynamic_loading = LIBAURA_DEFAULT_ALLOW_DYNAMIC_LOADING;
    config->log_file = string_copy(LIBAURA_DEFAULT_LOG_FILE);
    config->config_file = string_copy(LIBAURA_DEFAULT_CONFIG_FILE);
    config->features = LIBAURA_DEFAULT_FEATURES;
    
    if (!config->log_file || !config->config_file) {
        libaura_config_cleanup(config);
        return -1;
    }
    
    return 0;
}

void libaura_config_cleanup(libaura_container_config_t* config) {
    if (!config) {
        return;
    }
    
    /* Free allocated strings */
    free(config->log_file);
    free(config->config_file);
    
    /* Reset to default values */
    config->log_file = NULL;
    config->config_file = NULL;
}

int libaura_config_load(libaura_container_config_t* config, const char* file_path) {
    if (!config || !file_path) {
        return -1;
    }
    
    /* Open configuration file */
    FILE* file = fopen(file_path, "r");
    if (!file) {
        return -1;
    }
    
    /* Initialize with defaults first */
    libaura_config_init(config);
    
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
        libaura_config_set(config, key, value);
    }
    
    fclose(file);
    
    /* Update config_file */
    free(config->config_file);
    config->config_file = string_copy(file_path);
    
    return 0;
}

int libaura_config_save(const libaura_container_config_t* config, const char* file_path) {
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
    fprintf(file, "# LibAura Component Container Configuration\n");
    fprintf(file, "# Generated by LibAura v1.0.0\n");
    fprintf(file, "# Copyright © 2025 OBINexus Computing - Computing from the Heart\n\n");
    
    /* Write configuration values */
    fprintf(file, "initial_capacity=%zu\n", config->initial_capacity);
    fprintf(file, "max_components=%zu\n", config->max_components);
    
    /* Convert security level to string */
    const char* security_str = "medium";
    switch (config->security) {
        case LIBAURA_SECURITY_LOW:
            security_str = "low";
            break;
        case LIBAURA_SECURITY_MEDIUM:
            security_str = "medium";
            break;
        case LIBAURA_SECURITY_HIGH:
            security_str = "high";
            break;
        case LIBAURA_SECURITY_QUANTUM:
            security_str = "quantum";
            break;
    }
    fprintf(file, "security=%s\n", security_str);
    
    /* Write boolean values */
    fprintf(file, "verify_on_resolve=%s\n", config->verify_on_resolve ? "true" : "false");
    fprintf(file, "verify_entropy=%s\n", config->verify_entropy ? "true" : "false");
    fprintf(file, "allow_dynamic_loading=%s\n", config->allow_dynamic_loading ? "true" : "false");
    
    /* Write string values */
    fprintf(file, "log_file=%s\n", config->log_file ? config->log_file : "");
    
    /* Write features */
    fprintf(file, "features=0x%08X\n", config->features);
    
    fclose(file);
    
    return 0;
}

int libaura_config_set(libaura_container_config_t* config, const char* key, const char* value) {
    if (!config || !key || !value) {
        return -1;
    }
    
    /* Handle different configuration keys */
    if (strcmp(key, "initial_capacity") == 0) {
        config->initial_capacity = atoi(value);
    } else if (strcmp(key, "max_components") == 0) {
        config->max_components = atoi(value);
    } else if (strcmp(key, "security") == 0) {
        if (strcmp(value, "low") == 0) {
            config->security = LIBAURA_SECURITY_LOW;
        } else if (strcmp(value, "medium") == 0) {
            config->security = LIBAURA_SECURITY_MEDIUM;
        } else if (strcmp(value, "high") == 0) {
            config->security = LIBAURA_SECURITY_HIGH;
        } else if (strcmp(value, "quantum") == 0) {
            config->security = LIBAURA_SECURITY_QUANTUM;
        }
    } else if (strcmp(key, "verify_on_resolve") == 0) {
        config->verify_on_resolve = (strcmp(value, "true") == 0);
    } else if (strcmp(key, "verify_entropy") == 0) {
        config->verify_entropy = (strcmp(value, "true") == 0);
    } else if (strcmp(key, "allow_dynamic_loading") == 0) {
        config->allow_dynamic_loading = (strcmp(value, "true") == 0);
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

int libaura_config_get(const libaura_container_config_t* config, const char* key, 
                     char* value, size_t value_size) {
    if (!config || !key || !value || value_size == 0) {
        return -1;
    }
    
    /* Handle different configuration keys */
    if (strcmp(key, "initial_capacity") == 0) {
        snprintf(value, value_size, "%zu", config->initial_capacity);
    } else if (strcmp(key, "max_components") == 0) {
        snprintf(value, value_size, "%zu", config->max_components);
    } else if (strcmp(key, "security") == 0) {
        switch (config->security) {
            case LIBAURA_SECURITY_LOW:
                snprintf(value, value_size, "low");
                break;
            case LIBAURA_SECURITY_MEDIUM:
                snprintf(value, value_size, "medium");
                break;
            case LIBAURA_SECURITY_HIGH:
                snprintf(value, value_size, "high");
                break;
            case LIBAURA_SECURITY_QUANTUM:
                snprintf(value, value_size, "quantum");
                break;
            default:
                snprintf(value, value_size, "unknown");
                break;
        }
    } else if (strcmp(key, "verify_on_resolve") == 0) {
        snprintf(value, value_size, "%s", config->verify_on_resolve ? "true" : "false");
    } else if (strcmp(key, "verify_entropy") == 0) {
        snprintf(value, value_size, "%s", config->verify_entropy ? "true" : "false");
    } else if (strcmp(key, "allow_dynamic_loading") == 0) {
        snprintf(value, value_size, "%s", config->allow_dynamic_loading ? "true" : "false");
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

int libaura_config_create_default(const char* file_path) {
    if (!file_path) {
        return -1;
    }
    
    /* Create default configuration */
    libaura_container_config_t config;
    if (libaura_config_init(&config) != 0) {
        return -1;
    }
    
    /* Save configuration to file */
    int result = libaura_config_save(&config, file_path);
    
    /* Clean up */
    libaura_config_cleanup(&config);
    
    return result;
}