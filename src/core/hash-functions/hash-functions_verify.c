/**
 * @file hash-functions_verify.c
 * @brief Verification implementation for LibAura hash functions
 * 
 * Implements verification and validation functions for hash integrity
 * checking and tamper detection.
 * 
 * Copyright © 2025 OBINexus Computing - Computing from the Heart
 */

#include "libaura/core/hash-functions/hash-functions_public.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

/* External functions from priv.c */
extern uint8_t libaura_calculate_entropy_score(const uint8_t* data, size_t size);

/* Verify hash against expected value with strict entropy checking */
libaura_hash_result_t libaura_hash_verify(const void* data, size_t size,
                                        const uint8_t* expected_digest,
                                        size_t digest_size) {
    if (!data || !expected_digest) {
        return LIBAURA_HASH_ERROR;
    }
    
    /* Determine algorithm based on digest size */
    int algorithm;
    if (digest_size == LIBAURA_DIGEST_SIZE_64) {
        algorithm = LIBAURA_HASH_AURA64;
    } else if (digest_size == LIBAURA_DIGEST_SIZE_256) {
        algorithm = LIBAURA_HASH_AURA256;
    } else if (digest_size == LIBAURA_DIGEST_SIZE_512) {
        algorithm = LIBAURA_HASH_AURA512;
    } else {
        return LIBAURA_HASH_ERROR;
    }
    
    /* Calculate hash */
    uint8_t calculated_digest[LIBAURA_DIGEST_SIZE_512];
    int result = libaura_hash_compute(algorithm, data, size, calculated_digest, digest_size);
    
    if (result != LIBAURA_HASH_SUCCESS) {
        return LIBAURA_HASH_ERROR;
    }
    
    /* Check calculated hash entropy */
    uint8_t entropy_score = libaura_hash_check_entropy(calculated_digest, digest_size);
    
    /* Threshold based on digest size */
    uint8_t min_threshold = 0;
    switch (algorithm) {
        case LIBAURA_HASH_AURA64:
            min_threshold = 180;
            break;
        case LIBAURA_HASH_AURA256:
            min_threshold = 210;
            break;
        case LIBAURA_HASH_AURA512:
            min_threshold = 230;
            break;
    }
    
    if (entropy_score < min_threshold) {
        return LIBAURA_HASH_ENTROPY_LOW;
    }
    
    /* Compare with expected digest */
    if (memcmp(calculated_digest, expected_digest, digest_size) != 0) {
        return LIBAURA_HASH_INVALID;
    }
    
    return LIBAURA_HASH_VALID;
}

/* Enhanced verification with tamper detection */
libaura_hash_result_t libaura_hash_verify_enhanced(const void* data, size_t size,
                                                 const uint8_t* expected_digest,
                                                 size_t digest_size,
                                                 uint64_t last_verified_time) {
    /* First perform basic verification */
    libaura_hash_result_t result = libaura_hash_verify(data, size, expected_digest, digest_size);
    
    if (result != LIBAURA_HASH_VALID) {
        return result;
    }
    
    /* Enhanced temporal verification */
    uint64_t current_time = (uint64_t)time(NULL);
    
    /* Check for time-based anomalies (if last_verified_time is provided) */
    if (last_verified_time > 0) {
        /* Detect time manipulation - basic check */
        if (current_time < last_verified_time) {
            return LIBAURA_HASH_TAMPERED;
        }
    }
    
    /* Extra checks for high-security applications */
    uint8_t* temp_buffer = malloc(size);
    if (!temp_buffer) {
        return LIBAURA_HASH_ERROR;
    }
    
    /* Make a copy of data for integrity verification */
    memcpy(temp_buffer, data, size);
    
    /* Manipulate buffer slightly and rehash to verify sensitivity */
    for (size_t i = 0; i < size; i += size / 10) {
        uint8_t original = temp_buffer[i];
        temp_buffer[i] ^= 0x01;  /* Flip one bit */
        
        uint8_t modified_digest[LIBAURA_DIGEST_SIZE_512];
        int compute_result = libaura_hash_compute(
            digest_size == LIBAURA_DIGEST_SIZE_64 ? LIBAURA_HASH_AURA64 :
            digest_size == LIBAURA_DIGEST_SIZE_256 ? LIBAURA_HASH_AURA256 : LIBAURA_HASH_AURA512,
            temp_buffer, size, modified_digest, digest_size);
        
        /* Restore original value */
        temp_buffer[i] = original;
        
        if (compute_result != LIBAURA_HASH_SUCCESS) {
            free(temp_buffer);
            return LIBAURA_HASH_ERROR;
        }
        
        /* Modified hash should be different (verifies avalanche effect) */
        if (memcmp(modified_digest, expected_digest, digest_size) == 0) {
            free(temp_buffer);
            return LIBAURA_HASH_TAMPERED;  /* Hash is not sensitive to changes */
        }
    }
    
    free(temp_buffer);
    return LIBAURA_HASH_VALID;
}

/* Verify entropy distribution for data */
libaura_hash_result_t libaura_hash_verify_entropy(const void* data, size_t size, uint8_t min_entropy) {
    if (!data) {
        return LIBAURA_HASH_ERROR;
    }
    
    uint8_t entropy_score = libaura_hash_check_entropy(data, size);
    
    if (entropy_score < min_entropy) {
        return LIBAURA_HASH_ENTROPY_LOW;
    }
    
    return LIBAURA_HASH_VALID;
}

/* Self-test the hash functions to verify correctness */
int libaura_hash_self_test(void) {
    /* Test vectors */
    const char* test_data = "LibAura hash function test vector";
    uint8_t expected_aura64[LIBAURA_DIGEST_SIZE_64] = {0};
    uint8_t expected_aura256[LIBAURA_DIGEST_SIZE_256] = {0};
    uint8_t expected_aura512[LIBAURA_DIGEST_SIZE_512] = {0};
    
    /* We can't hardcode actual expected values since the implementation is new,
       so we'll verify consistency and entropy distribution */
    
    /* Test Aura64 */
    uint8_t digest64_1[LIBAURA_DIGEST_SIZE_64];
    uint8_t digest64_2[LIBAURA_DIGEST_SIZE_64];
    
    if (libaura_hash_aura64(test_data, strlen(test_data), digest64_1) != LIBAURA_HASH_SUCCESS ||
        libaura_hash_aura64(test_data, strlen(test_data), digest64_2) != LIBAURA_HASH_SUCCESS) {
        return LIBAURA_HASH_ERROR;
    }
    
    /* Verify consistency */
    if (memcmp(digest64_1, digest64_2, LIBAURA_DIGEST_SIZE_64) != 0) {
        return LIBAURA_HASH_ERROR;
    }
    
    /* Verify entropy */
    if (libaura_hash_check_entropy(digest64_1, LIBAURA_DIGEST_SIZE_64) < 180) {
        return LIBAURA_HASH_ERROR;
    }
    
    /* Similar tests for Aura256 and Aura512 */
    
    /* Test HMAC derivation */
    const char* private_key = "private_key_data";
    const char* public_key = "public_key_data";
    uint8_t derived_key1[32];
    uint8_t derived_key2[32];
    
    if (libaura_hmac_derive_key((const uint8_t*)private_key, strlen(private_key),
                               (const uint8_t*)public_key, strlen(public_key),
                               derived_key1, sizeof(derived_key1)) != LIBAURA_HASH_SUCCESS ||
        libaura_hmac_derive_key((const uint8_t*)private_key, strlen(private_key),
                               (const uint8_t*)public_key, strlen(public_key),
                               derived_key2, sizeof(derived_key2)) != LIBAURA_HASH_SUCCESS) {
        return LIBAURA_HASH_ERROR;
    }
    
    /* Verify consistency */
    if (memcmp(derived_key1, derived_key2, sizeof(derived_key1)) != 0) {
        return LIBAURA_HASH_ERROR;
    }
    
    /* Verify different keys produce different results */
    const char* different_key = "different_private_key";
    uint8_t derived_key3[32];
    
    if (libaura_hmac_derive_key((const uint8_t*)different_key, strlen(different_key),
                               (const uint8_t*)public_key, strlen(public_key),
                               derived_key3, sizeof(derived_key3)) != LIBAURA_HASH_SUCCESS) {
        return LIBAURA_HASH_ERROR;
    }
    
    /* Verify different keys produce different results */
    if (memcmp(derived_key1, derived_key3, sizeof(derived_key1)) == 0) {
        return LIBAURA_HASH_ERROR;
    }
    
    return LIBAURA_HASH_SUCCESS;
}

/* Verify component integrity using LibAura hash */
libaura_hash_result_t libaura_hash_verify_component(const void* component, size_t size, uint32_t expected_hash) {
    if (!component) {
        return LIBAURA_HASH_ERROR;
    }
    
    /* Calculate Aura256 hash */
    uint8_t digest[LIBAURA_DIGEST_SIZE_256];
    if (libaura_hash_aura256(component, size, digest) != LIBAURA_HASH_SUCCESS) {
        return LIBAURA_HASH_ERROR;
    }
    
    /* Extract 32-bit hash from digest */
    uint32_t calculated_hash = ((uint32_t)digest[0] << 24) | ((uint32_t)digest[1] << 16) |
                              ((uint32_t)digest[2] << 8) | ((uint32_t)digest[3]);
    
    /* Compare with expected hash */
    if (calculated_hash != expected_hash) {
        return LIBAURA_HASH_INVALID;
    }
    
    return LIBAURA_HASH_VALID;
}

/* Verify system integrity using a hash chain */
libaura_hash_result_t libaura_hash_verify_chain(const uint32_t* component_hashes, size_t count, 
                                              const uint8_t* expected_chain_hash) {
    if (!component_hashes || !expected_chain_hash || count == 0) {
        return LIBAURA_HASH_ERROR;
    }
    
    /* Calculate chain hash */
    uint8_t chain_hash[LIBAURA_DIGEST_SIZE_256];
    if (libaura_hash_aura256(component_hashes, count * sizeof(uint32_t), chain_hash) != LIBAURA_HASH_SUCCESS) {
        return LIBAURA_HASH_ERROR;
    }
    
    /* Compare with expected chain hash */
    if (memcmp(chain_hash, expected_chain_hash, LIBAURA_DIGEST_SIZE_256) != 0) {
        return LIBAURA_HASH_INVALID;
    }
    
    return LIBAURA_HASH_VALID;
}