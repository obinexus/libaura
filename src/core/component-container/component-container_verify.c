/**
 * @file component-container_verify.c
 * @brief Implementation of verification interface for component container
 * 
 * Implements the zero-knowledge verification system for components
 * using the formal proof principles and Schnorr identification protocol.
 * 
 * Copyright © 2025 OBINexus Computing - Computing from the Heart
 */

#include "libaura/core/component-container/component-container_verify.h"
#include "component-container_priv.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

/* OpenSSL includes */
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

/* Constants */
#define LIBAURA_VERIFY_CHALLENGE_SIZE 32
#define LIBAURA_VERIFY_RESPONSE_SIZE 64
#define LIBAURA_VERIFY_PROOF_SIZE 64
#define LIBAURA_VERIFY_MAX_CHALLENGES 5
#define LIBAURA_VERIFY_CHALLENGE_TIMEOUT 300 /* 5 minutes */

/* Verification context structure */
struct libaura_verify_context {
    uint8_t context_id[32];
    uint64_t creation_time;
    uint32_t challenge_counter;
    
    /* Challenge tracking */
    struct {
        uint8_t challenge[LIBAURA_VERIFY_CHALLENGE_SIZE];
        uint64_t timestamp;
        bool used;
    } challenges[LIBAURA_VERIFY_MAX_CHALLENGES];
    
    /* Entropy analysis state */
    uint8_t entropy_map[256];
    double last_entropy_score;
};

/* Static mapping of verification results to error messages */
static const char* error_messages[] = {
    "Verification succeeded",                        /* LIBAURA_VERIFY_SUCCESS */
    "Verification failed",                           /* LIBAURA_VERIFY_FAILED */
    "Error during verification",                     /* LIBAURA_VERIFY_ERROR */
    "Component has been tampered with",              /* LIBAURA_VERIFY_TAMPERED */
    "Component has expired",                         /* LIBAURA_VERIFY_EXPIRED */
    "Challenge-response verification failed",        /* LIBAURA_VERIFY_CHALLENGE_FAILED */
    "Zero-knowledge proof is invalid",               /* LIBAURA_VERIFY_PROOF_INVALID */
    "Entropy distribution check failed"              /* LIBAURA_VERIFY_ENTROPY_LOW */
};

/* Create verification context */
libaura_verify_context_t* libaura_verify_create_context(void) {
    libaura_verify_context_t* context = malloc(sizeof(libaura_verify_context_t));
    if (!context) {
        return NULL;
    }
    
    /* Generate unique context ID */
    if (RAND_bytes(context->context_id, sizeof(context->context_id)) != 1) {
        free(context);
        return NULL;
    }
    
    /* Initialize context */
    context->creation_time = (uint64_t)time(NULL);
    context->challenge_counter = 0;
    
    /* Clear challenge tracking */
    memset(context->challenges, 0, sizeof(context->challenges));
    
    /* Clear entropy analysis state */
    memset(context->entropy_map, 0, sizeof(context->entropy_map));
    context->last_entropy_score = 0.0;
    
    return context;
}

/* Destroy verification context */
void libaura_verify_destroy_context(libaura_verify_context_t* context) {
    if (!context) {
        return;
    }
    
    /* Clear sensitive data */
    memset(context, 0, sizeof(libaura_verify_context_t));
    
    /* Free context */
    free(context);
}

/* Verify a component */
libaura_verify_result_t libaura_verify_component_data(libaura_verify_context_t* context,
                                                 const void* component,
                                                 size_t size,
                                                 uint32_t expected_hash) {
    if (!context || !component || size == 0) {
        return LIBAURA_VERIFY_ERROR;
    }
    
    /* Calculate hash of component */
    uint32_t calculated_hash = libaura_generate_component_hash(component, size);
    
    /* Compare with expected hash */
    if (calculated_hash != expected_hash) {
        return LIBAURA_VERIFY_TAMPERED;
    }
    
    return LIBAURA_VERIFY_SUCCESS;
}

/* Generate verification challenge */
int libaura_verify_generate_challenge(libaura_verify_context_t* context,
                                     uint8_t* challenge,
                                     size_t challenge_size) {
    if (!context || !challenge || challenge_size < LIBAURA_VERIFY_CHALLENGE_SIZE) {
        return -1;
    }
    
    /* Find unused challenge slot */
    int slot = -1;
    for (int i = 0; i < LIBAURA_VERIFY_MAX_CHALLENGES; i++) {
        if (!context->challenges[i].used) {
            slot = i;
            break;
        }
    }
    
    /* If all slots are used, overwrite the oldest */
    if (slot == -1) {
        uint64_t oldest = UINT64_MAX;
        for (int i = 0; i < LIBAURA_VERIFY_MAX_CHALLENGES; i++) {
            if (context->challenges[i].timestamp < oldest) {
                oldest = context->challenges[i].timestamp;
                slot = i;
            }
        }
    }
    
    /* Generate random challenge */
    if (RAND_bytes(context->challenges[slot].challenge, LIBAURA_VERIFY_CHALLENGE_SIZE) != 1) {
        return -1;
    }
    
    /* Set challenge metadata */
    context->challenges[slot].timestamp = (uint64_t)time(NULL);
    context->challenges[slot].used = true;
    
    /* Copy challenge to output buffer */
    memcpy(challenge, context->challenges[slot].challenge, LIBAURA_VERIFY_CHALLENGE_SIZE);
    
    /* Increment challenge counter */
    context->challenge_counter++;
    
    return 0;
}

/* Verify challenge response */
libaura_verify_result_t libaura_verify_challenge_response(libaura_verify_context_t* context,
                                                     const uint8_t* challenge,
                                                     size_t challenge_size,
                                                     const uint8_t* response,
                                                     size_t response_size,
                                                     const uint8_t* public_key,
                                                     size_t public_key_size) {
    if (!context || !challenge || challenge_size < LIBAURA_VERIFY_CHALLENGE_SIZE ||
        !response || response_size < LIBAURA_VERIFY_RESPONSE_SIZE ||
        !public_key || public_key_size == 0) {
        return LIBAURA_VERIFY_ERROR;
    }
    
    /* Find matching challenge */
    int slot = -1;
    for (int i = 0; i < LIBAURA_VERIFY_MAX_CHALLENGES; i++) {
        if (context->challenges[i].used &&
            memcmp(context->challenges[i].challenge, challenge, LIBAURA_VERIFY_CHALLENGE_SIZE) == 0) {
            slot = i;
            break;
        }
    }
    
    /* If challenge not found */
    if (slot == -1) {
        return LIBAURA_VERIFY_CHALLENGE_FAILED;
    }
    
    /* Check challenge timeout */
    uint64_t current_time = (uint64_t)time(NULL);
    if (current_time - context->challenges[slot].timestamp > LIBAURA_VERIFY_CHALLENGE_TIMEOUT) {
        /* Mark challenge as unused */
        context->challenges[slot].used = false;
        return LIBAURA_VERIFY_EXPIRED;
    }
    
    /* Verify response using HMAC validation */
    uint8_t expected_response[LIBAURA_VERIFY_RESPONSE_SIZE];
    unsigned int output_len = LIBAURA_VERIFY_RESPONSE_SIZE;
    
    /* Create validation context using public key and challenge */
    HMAC_CTX* hmac_ctx = HMAC_CTX_new();
    if (!hmac_ctx) {
        return LIBAURA_VERIFY_ERROR;
    }
    
    int result = LIBAURA_VERIFY_ERROR;
    
    /* Initialize HMAC with public key */
    if (HMAC_Init_ex(hmac_ctx, public_key, public_key_size, EVP_sha512(), NULL) &&
        HMAC_Update(hmac_ctx, challenge, challenge_size) &&
        HMAC_Update(hmac_ctx, context->context_id, sizeof(context->context_id)) &&
        HMAC_Final(hmac_ctx, expected_response, &output_len)) {
        
        /* Compare with provided response */
        if (memcmp(expected_response, response, LIBAURA_VERIFY_RESPONSE_SIZE) == 0) {
            result = LIBAURA_VERIFY_SUCCESS;
        } else {
            result = LIBAURA_VERIFY_CHALLENGE_FAILED;
        }
    }
    
    /* Clean up HMAC context */
    HMAC_CTX_free(hmac_ctx);
    
    /* Mark challenge as unused after verification */
    context->challenges[slot].used = false;
    
    return result;
}

/* Create zero-knowledge proof */
int libaura_verify_create_proof(libaura_verify_context_t* context,
                              const uint8_t* private_key,
                              size_t private_key_size,
                              const uint8_t* challenge,
                              size_t challenge_size,
                              uint8_t* proof,
                              size_t* proof_size) {
    if (!context || !private_key || private_key_size == 0 ||
        !challenge || challenge_size == 0 ||
        !proof || !proof_size || *proof_size < LIBAURA_VERIFY_PROOF_SIZE) {
        return -1;
    }
    
    /* Create proof using Schnorr protocol */
    uint32_t component_hash = 0; /* Not used directly in proof creation */
    size_t output_size = *proof_size;
    
    int result = libaura_create_zkp(component_hash, private_key, private_key_size,
                                   challenge, challenge_size, proof, &output_size);
    
    if (result == 0) {
        *proof_size = output_size;
    }
    
    return result;
}

/* Verify zero-knowledge proof */
libaura_verify_result_t libaura_verify_proof(libaura_verify_context_t* context,
                                        const uint8_t* public_key,
                                        size_t public_key_size,
                                        const uint8_t* challenge,
                                        size_t challenge_size,
                                        const uint8_t* proof,
                                        size_t proof_size) {
    if (!context || !public_key || public_key_size == 0 ||
        !challenge || challenge_size == 0 ||
        !proof || proof_size < LIBAURA_VERIFY_PROOF_SIZE) {
        return LIBAURA_VERIFY_ERROR;
    }
    
    /* Verify proof using Schnorr protocol */
    uint32_t component_hash = 0; /* Not used directly in proof verification */
    
    int result = libaura_verify_zkp(component_hash, public_key, public_key_size,
                                   challenge, challenge_size, proof, proof_size);
    
    return result == 0 ? LIBAURA_VERIFY_SUCCESS : LIBAURA_VERIFY_PROOF_INVALID;
}

/* Calculate Shannon entropy for entropy distribution analysis */
static double calculate_shannon_entropy(const uint8_t* data, size_t size) {
    if (!data || size == 0) {
        return 0.0;
    }
    
    /* Count frequencies of each byte value */
    unsigned int frequencies[256] = {0};
    for (size_t i = 0; i < size; i++) {
        frequencies[data[i]]++;
    }
    
    /* Calculate Shannon entropy */
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (frequencies[i] > 0) {
            double p = (double)frequencies[i] / size;
            entropy -= p * log2(p);
        }
    }
    
    return entropy;
}

/* Check entropy distribution */
libaura_verify_result_t libaura_verify_entropy(libaura_verify_context_t* context,
                                          const void* data,
                                          size_t size,
                                          uint8_t min_entropy) {
    if (!context || !data || size == 0) {
        return LIBAURA_VERIFY_ERROR;
    }
    
    /* Calculate entropy score */
    int entropy_score = libaura_verify_get_entropy_score(context, data, size);
    
    if (entropy_score < 0) {
        return LIBAURA_VERIFY_ERROR;
    }
    
    /* Compare with minimum entropy */
    if ((uint8_t)entropy_score < min_entropy) {
        return LIBAURA_VERIFY_ENTROPY_LOW;
    }
    
    return LIBAURA_VERIFY_SUCCESS;
}

/* Get entropy score */
int libaura_verify_get_entropy_score(libaura_verify_context_t* context,
                                    const void* data,
                                    size_t size) {
    if (!context || !data || size == 0) {
        return -1;
    }
    
    /* Calculate SHA-256 hash */
    uint8_t hash[32];
    SHA256_CTX sha_ctx;
    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, data, size);
    SHA256_Final(hash, &sha_ctx);
    
    /* Count byte frequencies for entropy analysis */
    memset(context->entropy_map, 0, sizeof(context->entropy_map));
    for (size_t i = 0; i < sizeof(hash); i++) {
        context->entropy_map[hash[i]]++;
    }
    
    /* Calculate Shannon entropy */
    double entropy = calculate_shannon_entropy(hash, sizeof(hash));
    context->last_entropy_score = entropy;
    
    /* Normalize to 0-255 range */
    int entropy_score = (int)((entropy / 8.0) * 255.0);
    
    return entropy_score;
}

/* Get error message for verification result */
const char* libaura_verify_get_error_message(libaura_verify_result_t result) {
    /* Convert result to index (negative results are error codes) */
    int index = -result;
    
    /* Boundary check */
    if (index < 0 || index >= (int)(sizeof(error_messages) / sizeof(error_messages[0]))) {
        return "Unknown error";
    }
    
    return error_messages[index];
}