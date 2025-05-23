/**
 * @file test_hash_bridge.c
 * @brief Test suite for the hash-function and checksum-verification bridge
 * 
 * Validates the integration between hash-functions and checksum-verification modules,
 * ensuring proper hardness, soundness, and completeness properties.
 * 
 * Copyright © 2025 OBINexus Computing - Computing from the Heart
 */

#include "libaura/core/checksum-verification/checksum-verification_public.h"
#include "libaura/core/checksum-verification/checksum-verification_hash_bridge.h"
#include "libaura/core/hash-functions/hash-functions_public.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* Test data */
static const char* test_data = "LibAura test vector for hash-checksum integration";
static const char* test_private_key = "LibAura private key for test";
static const char* test_public_key = "LibAura public key for test";

/* Test function declarations */
static void test_aura64_verification(void);
static void test_aura256_verification(void);
static void test_aura512_verification(void);
static void test_hmac_verification(void);
static void test_entropy_verification(void);
static void test_tamper_detection(void);
static void test_edge_cases(void);

/* Main test function */
int main(void) {
    printf("Starting LibAura hash-checksum integration tests...\n");
    
    /* Initialize hash functions for checksum verification */
    if (libaura_checksum_hash_initialize() != 0) {
        fprintf(stderr, "Failed to initialize hash functions\n");
        return 1;
    }
    
    /* Run tests */
    test_aura64_verification();
    test_aura256_verification();
    test_aura512_verification();
    test_hmac_verification();
    test_entropy_verification();
    test_tamper_detection();
    test_edge_cases();
    
    /* Clean up */
    libaura_checksum_hash_cleanup();
    
    printf("All tests passed successfully!\n");
    return 0;
}

/* Test Aura64 verification */
static void test_aura64_verification(void) {
    printf("Testing Aura64 verification... ");
    
    /* Create verification options */
    libaura_checksum_options_t options = {
        .algorithm = LIBAURA_CHECKSUM_ALGORITHM_AURA64,
        .verify_entropy = true,
        .enhanced_verification = false,
        .last_verification_time = 0
    };
    
    /* Create context */
    void* ctx = libaura_checksum_hash_create_context(&options);
    assert(ctx != NULL);
    
    /* Update context with test data */
    assert(libaura_checksum_hash_update(ctx, test_data, strlen(test_data)) == 0);
    
    /* Finalize and get checksum */
    uint8_t checksum[LIBAURA_DIGEST_SIZE_64];
    assert(libaura_checksum_hash_finalize(ctx, checksum, sizeof(checksum)) == 0);
    
    /* Verify checksum */
    libaura_checksum_result_t result = libaura_checksum_hash_verify(
        &options, test_data, strlen(test_data), checksum, sizeof(checksum));
    assert(result == LIBAURA_CHECKSUM_VALID);
    
    /* Test with modified data (soundness property) */
    char modified_data[100];
    strcpy(modified_data, test_data);
    modified_data[0] ^= 0x01; /* Flip one bit */
    
    result = libaura_checksum_hash_verify(
        &options, modified_data, strlen(modified_data), checksum, sizeof(checksum));
    assert(result != LIBAURA_CHECKSUM_VALID);
    
    /* Destroy context */
    libaura_checksum_hash_destroy_context(ctx);
    
    printf("Passed\n");
}

/* Test Aura256 verification */
static void test_aura256_verification(void) {
    printf("Testing Aura256 verification... ");
    
    /* Create verification options */
    libaura_checksum_options_t options = {
        .algorithm = LIBAURA_CHECKSUM_ALGORITHM_AURA256,
        .verify_entropy = true,
        .enhanced_verification = false,
        .last_verification_time = 0
    };
    
    /* Create context */
    void* ctx = libaura_checksum_hash_create_context(&options);
    assert(ctx != NULL);
    
    /* Update context with test data */
    assert(libaura_checksum_hash_update(ctx, test_data, strlen(test_data)) == 0);
    
    /* Finalize and get checksum */
    uint8_t checksum[LIBAURA_DIGEST_SIZE_256];
    assert(libaura_checksum_hash_finalize(ctx, checksum, sizeof(checksum)) == 0);
    
    /* Verify checksum */
    libaura_checksum_result_t result = libaura_checksum_hash_verify(
        &options, test_data, strlen(test_data), checksum, sizeof(checksum));
    assert(result == LIBAURA_CHECKSUM_VALID);
    
    /* Test with modified data (soundness property) */
    char modified_data[100];
    strcpy(modified_data, test_data);
    modified_data[0] ^= 0x01; /* Flip one bit */
    
    result = libaura_checksum_hash_verify(
        &options, modified_data, strlen(modified_data), checksum, sizeof(checksum));
    assert(result != LIBAURA_CHECKSUM_VALID);
    
    /* Destroy context */
    libaura_checksum_hash_destroy_context(ctx);
    
    printf("Passed\n");
}

/* Test Aura512 verification */
static void test_aura512_verification(void) {
    printf("Testing Aura512 verification... ");
    
    /* Create verification options */
    libaura_checksum_options_t options = {
        .algorithm = LIBAURA_CHECKSUM_ALGORITHM_AURA512,
        .verify_entropy = true,
        .enhanced_verification = false,
        .last_verification_time = 0
    };
    
    /* Create context */
    void* ctx = libaura_checksum_hash_create_context(&options);
    assert(ctx != NULL);
    
    /* Update context with test data */
    assert(libaura_checksum_hash_update(ctx, test_data, strlen(test_data)) == 0);
    
    /* Finalize and get checksum */
    uint8_t checksum[LIBAURA_DIGEST_SIZE_512];
    assert(libaura_checksum_hash_finalize(ctx, checksum, sizeof(checksum)) == 0);
    
    /* Verify checksum */
    libaura_checksum_result_t result = libaura_checksum_hash_verify(
        &options, test_data, strlen(test_data), checksum, sizeof(checksum));
    assert(result == LIBAURA_CHECKSUM_VALID);
    
    /* Test with modified data (soundness property) */
    char modified_data[100];
    strcpy(modified_data, test_data);
    modified_data[0] ^= 0x01; /* Flip one bit */
    
    result = libaura_checksum_hash_verify(
        &options, modified_data, strlen(modified_data), checksum, sizeof(checksum));
    assert(result != LIBAURA_CHECKSUM_VALID);
    
    /* Destroy context */
    libaura_checksum_hash_destroy_context(ctx);
    
    printf("Passed\n");
}

/* Test HMAC verification */
static void test_hmac_verification(void) {
    printf("Testing HMAC verification... ");
    
    /* Create verification options */
    libaura_checksum_options_t options = {
        .algorithm = LIBAURA_CHECKSUM_ALGORITHM_AURA256,
        .verify_entropy = true,
        .enhanced_verification = false,
        .last_verification_time = 0
    };
    
    /* Compute HMAC derived key */
    uint8_t derived_key[LIBAURA_DIGEST_SIZE_256];
    assert(libaura_hmac_derive_key(
        (const uint8_t*)test_private_key, strlen(test_private_key),
        (const uint8_t*)test_public_key, strlen(test_public_key),
        derived_key, sizeof(derived_key)) == LIBAURA_HASH_SUCCESS);
    
    /* Verify HMAC derived key */
    libaura_checksum_result_t result = libaura_checksum_hash_verify_hmac_key(
        &options,
        (const uint8_t*)test_private_key, strlen(test_private_key),
        (const uint8_t*)test_public_key, strlen(test_public_key),
        derived_key, sizeof(derived_key));
    assert(result == LIBAURA_CHECKSUM_VALID);
    
    /* Test with modified private key (soundness property) */
    char modified_key[100];
    strcpy(modified_key, test_private_key);
    modified_key[0] ^= 0x01; /* Flip one bit */
    
    result = libaura_checksum_hash_verify_hmac_key(
        &options,
        (const uint8_t*)modified_key, strlen(modified_key),
        (const uint8_t*)test_public_key, strlen(test_public_key),
        derived_key, sizeof(derived_key));
    assert(result != LIBAURA_CHECKSUM_VALID);
    
    printf("Passed\n");
}

/* Test entropy verification */
static void test_entropy_verification(void) {
    printf("Testing entropy verification... ");
    
    /* Create verification options with entropy checking */
    libaura_checksum_options_t options = {
        .algorithm = LIBAURA_CHECKSUM_ALGORITHM_AURA256,
        .verify_entropy = true,
        .enhanced_verification = false,
        .last_verification_time = 0
    };
    
    /* Create context */
    void* ctx = libaura_checksum_hash_create_context(&options);
    assert(ctx != NULL);
    
    /* Update context with test data */
    assert(libaura_checksum_hash_update(ctx, test_data, strlen(test_data)) == 0);
    
    /* Finalize and get checksum */
    uint8_t checksum[LIBAURA_DIGEST_SIZE_256];
    assert(libaura_checksum_hash_finalize(ctx, checksum, sizeof(checksum)) == 0);
    
    /* Verify entropy score */
    uint8_t entropy_score = libaura_hash_check_entropy(checksum, sizeof(checksum));
    assert(entropy_score >= 200); /* Typical threshold for Aura256 */
    
    /* Destroy context */
    libaura_checksum_hash_destroy_context(ctx);
    
    printf("Passed\n");
}

/* Test tamper detection */
static void test_tamper_detection(void) {
    printf("Testing tamper detection... ");
    
    /* Create verification options with enhanced verification */
    libaura_checksum_options_t options = {
        .algorithm = LIBAURA_CHECKSUM_ALGORITHM_AURA256,
        .verify_entropy = true,
        .enhanced_verification = true,
        .last_verification_time = (uint64_t)time(NULL) - 3600 /* 1 hour ago */
    };
    
    /* Create context */
    void* ctx = libaura_checksum_hash_create_context(&options);
    assert(ctx != NULL);
    
    /* Update context with test data */
    assert(libaura_checksum_hash_update(ctx, test_data, strlen(test_data)) == 0);
    
    /* Finalize and get checksum */
    uint8_t checksum[LIBAURA_DIGEST_SIZE_256];
    assert(libaura_checksum_hash_finalize(ctx, checksum, sizeof(checksum)) == 0);
    
    /* Verify checksum with enhanced verification */
    libaura_checksum_result_t result = libaura_checksum_hash_verify(
        &options, test_data, strlen(test_data), checksum, sizeof(checksum));
    assert(result == LIBAURA_CHECKSUM_VALID);
    
    /* Test time-based tampering (set last verification time in the future) */
    options.last_verification_time = (uint64_t)time(NULL) + 3600; /* 1 hour in the future */
    
    result = libaura_checksum_hash_verify(
        &options, test_data, strlen(test_data), checksum, sizeof(checksum));
    assert(result == LIBAURA_CHECKSUM_TAMPERED);
    
    /* Destroy context */
    libaura_checksum_hash_destroy_context(ctx);
    
    printf("Passed\n");
}

/* Test edge cases */
static void test_edge_cases(void) {
    printf("Testing edge cases... ");
    
    /* Create verification options */
    libaura_checksum_options_t options = {
        .algorithm = LIBAURA_CHECKSUM_ALGORITHM_AURA256,
        .verify_entropy = true,
        .enhanced_verification = false,
        .last_verification_time = 0
    };
    
    /* Test 1: Empty data */
    void* ctx = libaura_checksum_hash_create_context(&options);
    assert(ctx != NULL);
    
    /* Update with empty data */
    assert(libaura_checksum_hash_update(ctx, "", 0) == 0);
    
    /* Finalize and get checksum */
    uint8_t checksum_empty[LIBAURA_DIGEST_SIZE_256];
    assert(libaura_checksum_hash_finalize(ctx, checksum_empty, sizeof(checksum_empty)) == 0);
    
    /* Verify empty data checksum */
    libaura_checksum_result_t result = libaura_checksum_hash_verify(
        &options, "", 0, checksum_empty, sizeof(checksum_empty));
    assert(result == LIBAURA_CHECKSUM_VALID);
    
    /* Destroy context */
    libaura_checksum_hash_destroy_context(ctx);
    
    /* Test 2: Null context operations (should fail gracefully) */
    assert(libaura_checksum_hash_update(NULL, test_data, strlen(test_data)) != 0);
    assert(libaura_checksum_hash_finalize(NULL, checksum_empty, sizeof(checksum_empty)) != 0);
    
    /* Test 3: Invalid algorithm */
    options.algorithm = 999; /* Invalid algorithm */
    assert(libaura_checksum_hash_create_context(&options) == NULL);
    
    /* Test 4: Small output buffer */
    options.algorithm = LIBAURA_CHECKSUM_ALGORITHM_AURA256;
    ctx = libaura_checksum_hash_create_context(&options);
    assert(ctx != NULL);
    
    /* Update context with test data */
    assert(libaura_checksum_hash_update(ctx, test_data, strlen(test_data)) == 0);
    
    /* Try to finalize with too small buffer */
    uint8_t small_buffer[LIBAURA_DIGEST_SIZE_64];
    assert(libaura_checksum_hash_finalize(ctx, small_buffer, sizeof(small_buffer)) != 0);
    
    /* Destroy context */
    libaura_checksum_hash_destroy_context(ctx);
    
    printf("Passed\n");
}