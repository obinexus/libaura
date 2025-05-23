/**
 * @file checksum-verification_hash_bridge.c
 * @brief Integration bridge between hash-functions and checksum-verification modules
 * 
 * Implements the integration layer that uses hash-functions module capabilities
 * within the checksum-verification system while maintaining proper configuration
 * and ensuring hardness, soundness, and completeness properties.
 * 
 * Copyright © 2025 OBINexus Computing - Computing from the Heart
 */

#include "libaura/core/checksum-verification/checksum-verification_public.h"
#include "libaura/core/checksum-verification/checksum-verification_priv.h"
#include "libaura/core/hash-functions/hash-functions_public.h"
#include "libaura/core/hash-functions/hash-functions_config.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/**
 * @brief Verification context with hash functions integration
 */
typedef struct {
    libaura_hash_context_t hash_ctx;
    libaura_checksum_options_t options;
    uint8_t entropy_threshold;
    uint8_t integrity_check[32];
    bool initialized;
} libaura_checksum_hash_context_t;

/* Static configuration */
static libaura_hash_config_t s_hash_config; 
static bool s_hash_initialized = false;

/**
 * @brief Initialize hash functions for checksum verification
 * @return 0 on success, non-zero on failure
 */
int libaura_checksum_hash_initialize(void) {
    if (s_hash_initialized) {
        return 0; /* Already initialized */
    }
    
    /* Initialize hash functions module */
    if (libaura_hash_initialize() != LIBAURA_HASH_SUCCESS) {
        return -1;
    }
    
    /* Initialize hash configuration with defaults */
    if (libaura_hash_config_init(&s_hash_config) != 0) {
        libaura_hash_cleanup();
        return -1;
    }
    
    /* Try to load configuration from default location */
    libaura_hash_config_load(&s_hash_config, s_hash_config.config_file);
    
    s_hash_initialized = true;
    return 0;
}

/**
 * @brief Clean up hash functions for checksum verification
 */
void libaura_checksum_hash_cleanup(void) {
    if (!s_hash_initialized) {
        return;
    }
    
    /* Clean up hash configuration */
    libaura_hash_config_cleanup(&s_hash_config);
    
    /* Clean up hash functions module */
    libaura_hash_cleanup();
    
    s_hash_initialized = false;
}

/**
 * @brief Create verification context using hash functions
 * @param options Checksum verification options
 * @return Verification context or NULL on failure
 */
void* libaura_checksum_hash_create_context(const libaura_checksum_options_t* options) {
    if (!s_hash_initialized && libaura_checksum_hash_initialize() != 0) {
        return NULL;
    }
    
    if (!options) {
        return NULL;
    }
    
    /* Allocate context */
    libaura_checksum_hash_context_t* context = malloc(sizeof(libaura_checksum_hash_context_t));
    if (!context) {
        return NULL;
    }
    
    /* Initialize context */
    memset(context, 0, sizeof(libaura_checksum_hash_context_t));
    
    /* Set options */
    context->options = *options;
    
    /* Initialize hash context based on options */
    libaura_digest_size_t digest_size;
    switch (options->algorithm) {
        case LIBAURA_CHECKSUM_ALGORITHM_AURA64:
            digest_size = LIBAURA_DIGEST_64;
            context->entropy_threshold = s_hash_config.min_entropy_aura64;
            break;
        case LIBAURA_CHECKSUM_ALGORITHM_AURA256:
            digest_size = LIBAURA_DIGEST_256;
            context->entropy_threshold = s_hash_config.min_entropy_aura256;
            break;
        case LIBAURA_CHECKSUM_ALGORITHM_AURA512:
            digest_size = LIBAURA_DIGEST_512;
            context->entropy_threshold = s_hash_config.min_entropy_aura512;
            break;
        default:
            /* Default to Aura256 */
            digest_size = LIBAURA_DIGEST_256;
            context->entropy_threshold = s_hash_config.min_entropy_aura256;
            break;
    }
    
    /* Initialize hash context */
    if (libaura_hash_init(&context->hash_ctx, digest_size) != LIBAURA_HASH_SUCCESS) {
        free(context);
        return NULL;
    }
    
    context->initialized = true;
    return context;
}

/**
 * @brief Destroy verification context created with hash functions
 * @param ctx Verification context
 */
void libaura_checksum_hash_destroy_context(void* ctx) {
    if (!ctx) {
        return;
    }
    
    libaura_checksum_hash_context_t* context = (libaura_checksum_hash_context_t*)ctx;
    
    /* Clear sensitive data */
    memset(context, 0, sizeof(libaura_checksum_hash_context_t));
    
    /* Free context */
    free(context);
}

/**
 * @brief Update verification context with data using hash functions
 * @param ctx Verification context
 * @param data Data to update with
 * @param size Size of data
 * @return 0 on success, non-zero on failure
 */
int libaura_checksum_hash_update(void* ctx, const void* data, size_t size) {
    if (!ctx || !data) {
        return -1;
    }
    
    libaura_checksum_hash_context_t* context = (libaura_checksum_hash_context_t*)ctx;
    
    /* Verify context is initialized */
    if (!context->initialized) {
        return -1;
    }
    
    /* Update hash context */
    if (libaura_hash_update(&context->hash_ctx, data, size) != LIBAURA_HASH_SUCCESS) {
        return -1;
    }
    
    return 0;
}

/**
 * @brief Finalize verification and get checksum using hash functions
 * @param ctx Verification context
 * @param checksum Output buffer for checksum
 * @param size Size of output buffer
 * @return 0 on success, non-zero on failure
 */
int libaura_checksum_hash_finalize(void* ctx, uint8_t* checksum, size_t size) {
    if (!ctx || !checksum) {
        return -1;
    }
    
    libaura_checksum_hash_context_t* context = (libaura_checksum_hash_context_t*)ctx;
    
    /* Verify context is initialized */
    if (!context->initialized) {
        return -1;
    }
    
    /* Determine required size based on algorithm */
    size_t required_size;
    libaura_hash_result_t (*hash_func)(const void*, size_t, uint8_t*);
    
    switch (context->options.algorithm) {
        case LIBAURA_CHECKSUM_ALGORITHM_AURA64:
            required_size = LIBAURA_DIGEST_SIZE_64;
            hash_func = libaura_hash_aura64;
            break;
        case LIBAURA_CHECKSUM_ALGORITHM_AURA256:
            required_size = LIBAURA_DIGEST_SIZE_256;
            hash_func = libaura_hash_aura256;
            break;
        case LIBAURA_CHECKSUM_ALGORITHM_AURA512:
            required_size = LIBAURA_DIGEST_SIZE_512;
            hash_func = libaura_hash_aura512;
            break;
        default:
            return -1;
    }
    
    /* Check output buffer size */
    if (size < required_size) {
        return -1;
    }
    
    /* Finalize hash */
    if (libaura_hash_final(&context->hash_ctx, checksum) != LIBAURA_HASH_SUCCESS) {
        return -1;
    }
    
    /* Verify entropy distribution if required */
    if (context->options.verify_entropy) {
        uint8_t entropy_score = libaura_hash_check_entropy(checksum, required_size);
        if (entropy_score < context->entropy_threshold) {
            return LIBAURA_CHECKSUM_ERROR_ENTROPY;
        }
    }
    
    return 0;
}

/**
 * @brief Verify checksum against data using hash functions
 * @param options Verification options
 * @param data Data to verify
 * @param size Size of data
 * @param expected_checksum Expected checksum
 * @param checksum_size Size of expected checksum
 * @return Verification result
 */
libaura_checksum_result_t libaura_checksum_hash_verify(
    const libaura_checksum_options_t* options,
    const void* data,
    size_t size,
    const uint8_t* expected_checksum,
    size_t checksum_size) {
        
    if (!options || !data || !expected_checksum) {
        return LIBAURA_CHECKSUM_ERROR;
    }
    
    /* Initialize if needed */
    if (!s_hash_initialized && libaura_checksum_hash_initialize() != 0) {
        return LIBAURA_CHECKSUM_ERROR;
    }
    
    /* Determine hash function based on checksum size */
    libaura_hash_result_t result;
    
    switch (options->algorithm) {
        case LIBAURA_CHECKSUM_ALGORITHM_AURA64:
            if (checksum_size < LIBAURA_DIGEST_SIZE_64) {
                return LIBAURA_CHECKSUM_ERROR;
            }
            
            /* Use enhanced verification if requested */
            if (options->enhanced_verification) {
                result = libaura_hash_verify_enhanced(data, size, 
                                                     expected_checksum, 
                                                     LIBAURA_DIGEST_SIZE_64,
                                                     options->last_verification_time);
            } else {
                result = libaura_hash_verify(data, size, 
                                           expected_checksum, 
                                           LIBAURA_DIGEST_SIZE_64);
            }
            break;
            
        case LIBAURA_CHECKSUM_ALGORITHM_AURA256:
            if (checksum_size < LIBAURA_DIGEST_SIZE_256) {
                return LIBAURA_CHECKSUM_ERROR;
            }
            
            /* Use enhanced verification if requested */
            if (options->enhanced_verification) {
                result = libaura_hash_verify_enhanced(data, size, 
                                                     expected_checksum, 
                                                     LIBAURA_DIGEST_SIZE_256,
                                                     options->last_verification_time);
            } else {
                result = libaura_hash_verify(data, size, 
                                           expected_checksum, 
                                           LIBAURA_DIGEST_SIZE_256);
            }
            break;
            
        case LIBAURA_CHECKSUM_ALGORITHM_AURA512:
            if (checksum_size < LIBAURA_DIGEST_SIZE_512) {
                return LIBAURA_CHECKSUM_ERROR;
            }
            
            /* Use enhanced verification if requested */
            if (options->enhanced_verification) {
                result = libaura_hash_verify_enhanced(data, size, 
                                                     expected_checksum, 
                                                     LIBAURA_DIGEST_SIZE_512,
                                                     options->last_verification_time);
            } else {
                result = libaura_hash_verify(data, size, 
                                           expected_checksum, 
                                           LIBAURA_DIGEST_SIZE_512);
            }
            break;
            
        default:
            return LIBAURA_CHECKSUM_ERROR;
    }
    
    /* Map hash result to checksum result */
    switch (result) {
        case LIBAURA_HASH_VALID:
            return LIBAURA_CHECKSUM_VALID;
        case LIBAURA_HASH_INVALID:
            return LIBAURA_CHECKSUM_INVALID;
        case LIBAURA_HASH_ENTROPY_LOW:
            return LIBAURA_CHECKSUM_ERROR_ENTROPY;
        case LIBAURA_HASH_TAMPERED:
            return LIBAURA_CHECKSUM_TAMPERED;
        default:
            return LIBAURA_CHECKSUM_ERROR;
    }
}

/**
 * @brief Verify HMAC derived key using hash functions
 * @param options Verification options
 * @param private_key Private key
 * @param private_key_len Private key length
 * @param public_key Public key
 * @param public_key_len Public key length
 * @param expected_key Expected derived key
 * @param key_size Size of expected key
 * @return Verification result
 */
libaura_checksum_result_t libaura_checksum_hash_verify_hmac_key(
    const libaura_checksum_options_t* options,
    const uint8_t* private_key,
    size_t private_key_len,
    const uint8_t* public_key,
    size_t public_key_len,
    const uint8_t* expected_key,
    size_t key_size) {
        
    if (!options || !private_key || !public_key || !expected_key) {
        return LIBAURA_CHECKSUM_ERROR;
    }
    
    /* Initialize if needed */
    if (!s_hash_initialized && libaura_checksum_hash_initialize() != 0) {
        return LIBAURA_CHECKSUM_ERROR;
    }
    
    /* Compute derived key */
    uint8_t derived_key[64]; /* Max size */
    size_t derived_key_size = key_size > sizeof(derived_key) ? sizeof(derived_key) : key_size;
    
    if (libaura_hmac_derive_key(private_key, private_key_len,
                              public_key, public_key_len,
                              derived_key, derived_key_size) != LIBAURA_HASH_SUCCESS) {
        return LIBAURA_CHECKSUM_ERROR;
    }
    
    /* Constant-time comparison to prevent timing attacks */
    int result = 0;
    for (size_t i = 0; i < derived_key_size; i++) {
        result |= derived_key[i] ^ expected_key[i];
    }
    
    /* Verify entropy if required */
    if (options->verify_entropy) {
        uint8_t entropy_score = libaura_hash_check_entropy(derived_key, derived_key_size);
        uint8_t threshold;
        
        switch (options->algorithm) {
            case LIBAURA_CHECKSUM_ALGORITHM_AURA64:
                threshold = s_hash_config.min_entropy_aura64;
                break;
            case LIBAURA_CHECKSUM_ALGORITHM_AURA256:
                threshold = s_hash_config.min_entropy_aura256;
                break;
            case LIBAURA_CHECKSUM_ALGORITHM_AURA512:
                threshold = s_hash_config.min_entropy_aura512;
                break;
            default:
                threshold = LIBAURA_MIN_ENTROPY_THRESHOLD;
                break;
        }
        
        if (entropy_score < threshold) {
            return LIBAURA_CHECKSUM_ERROR_ENTROPY;
        }
    }
    
    return result == 0 ? LIBAURA_CHECKSUM_VALID : LIBAURA_CHECKSUM_INVALID;
}

/**
 * @brief Register checksum hash verification functions with the component container
 * @param container_context Component container context
 * @return 0 on success, non-zero on failure
 */
int libaura_checksum_hash_register(void* container_context) {
    if (!container_context) {
        return -1;
    }
    
    /* Initialize if needed */
    if (!s_hash_initialized && libaura_checksum_hash_initialize() != 0) {
        return -1;
    }
    
    /* Register hash functions components */
    if (libaura_hash_register_components(container_context) != 0) {
        return -1;
    }
    
    /* Register hash configuration */
    if (libaura_hash_config_register(&s_hash_config, container_context) != 0) {
        return -1;
    }
    
    return 0;
}