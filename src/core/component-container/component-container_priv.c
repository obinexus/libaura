/**
 * @file component-container_priv.c
 * @brief Implementation of private component container functions
 * 
 * Contains the core zero-knowledge proof implementation and validation logic
 * following the Schnorr protocol described in the formal proof document.
 * 
 * Copyright © 2025 OBINexus Computing - Computing from the Heart
 */

#include "component-container_priv.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

/* OpenSSL includes */
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

/* Cryptographic constants */
#define LIBAURA_PRIME_P "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF"
#define LIBAURA_GENERATOR_G "2"

/* Global cryptographic parameters */
static BIGNUM *p = NULL;
static BIGNUM *g = NULL;
static BIGNUM *q = NULL;
static int initialized = 0;

/* Initialize cryptographic parameters */
static int initialize_crypto_params() {
    if (initialized) {
        return 0; /* Already initialized */
    }
    
    p = BN_new();
    g = BN_new();
    q = BN_new();
    
    if (!p || !g || !q) {
        return -1;
    }
    
    /* Set p and g */
    if (BN_hex2bn(&p, LIBAURA_PRIME_P) == 0 ||
        BN_hex2bn(&g, LIBAURA_GENERATOR_G) == 0) {
        return -1;
    }
    
    /* Calculate q = (p-1)/2 */
    BIGNUM *temp = BN_new();
    if (!temp) {
        return -1;
    }
    
    if (BN_copy(temp, p) == NULL ||
        BN_sub_word(temp, 1) == 0 ||
        BN_rshift1(q, temp) == 0) {
        BN_free(temp);
        return -1;
    }
    
    BN_free(temp);
    initialized = 1;
    
    return 0;
}

/* Cleanup cryptographic parameters */
static void cleanup_crypto_params() {
    if (p) {
        BN_free(p);
        p = NULL;
    }
    
    if (g) {
        BN_free(g);
        g = NULL;
    }
    
    if (q) {
        BN_free(q);
        q = NULL;
    }
    
    initialized = 0;
}

int libaura_verify_component(const void* component, size_t size, uint32_t expected_hash) {
    if (!component || size == 0) {
        return -1;
    }
    
    /* Calculate hash of component */
    uint32_t calculated_hash = libaura_generate_component_hash(component, size);
    
    /* Compare with expected hash */
    return (calculated_hash == expected_hash) ? 0 : -1;
}

int libaura_generate_challenge(uint8_t* challenge, size_t challenge_size) {
    if (!challenge || challenge_size == 0) {
        return -1;
    }
    
    /* Generate cryptographically secure random challenge */
    if (RAND_bytes(challenge, challenge_size) != 1) {
        return -1;
    }
    
    return 0;
}

int libaura_create_zkp(uint32_t component_hash,
                      const uint8_t* private_key, size_t private_key_size,
                      const uint8_t* challenge, size_t challenge_size,
                      uint8_t* proof, size_t* proof_size) {
    if (!private_key || private_key_size == 0 ||
        !challenge || challenge_size == 0 ||
        !proof || !proof_size || *proof_size < 64) {
        return -1;
    }
    
    /* Initialize cryptographic parameters if needed */
    if (!initialized && initialize_crypto_params() != 0) {
        return -1;
    }
    
    /* Create BN_CTX for calculations */
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        return -1;
    }
    
    /* Convert inputs to BIGNUMs */
    BIGNUM *x = BN_bin2bn(private_key, private_key_size, NULL);
    BIGNUM *c = BN_bin2bn(challenge, challenge_size, NULL);
    BIGNUM *r = BN_new();
    BIGNUM *s = BN_new();
    
    if (!x || !c || !r || !s) {
        BN_CTX_free(ctx);
        if (x) BN_free(x);
        if (c) BN_free(c);
        if (r) BN_free(r);
        if (s) BN_free(s);
        return -1;
    }
    
    /* Generate random value r */
    if (BN_rand_range(r, q) != 1) {
        BN_CTX_free(ctx);
        BN_free(x);
        BN_free(c);
        BN_free(r);
        BN_free(s);
        return -1;
    }
    
    /* Compute commitment t = g^r mod p */
    BIGNUM *t = BN_new();
    if (!t || BN_mod_exp(t, g, r, p, ctx) != 1) {
        BN_CTX_free(ctx);
        BN_free(x);
        BN_free(c);
        BN_free(r);
        BN_free(s);
        if (t) BN_free(t);
        return -1;
    }
    
    /* Compute response s = r + c*x mod q */
    BIGNUM *cx = BN_new();
    if (!cx || BN_mod_mul(cx, c, x, q, ctx) != 1 ||
        BN_mod_add(s, r, cx, q, ctx) != 1) {
        BN_CTX_free(ctx);
        BN_free(x);
        BN_free(c);
        BN_free(r);
        BN_free(s);
        BN_free(t);
        if (cx) BN_free(cx);
        return -1;
    }
    
    /* Convert t and s to binary */
    unsigned char t_bin[32] = {0};
    unsigned char s_bin[32] = {0};
    int t_len = BN_bn2binpad(t, t_bin, sizeof(t_bin));
    int s_len = BN_bn2binpad(s, s_bin, sizeof(s_bin));
    
    if (t_len <= 0 || s_len <= 0 || t_len + s_len > *proof_size) {
        BN_CTX_free(ctx);
        BN_free(x);
        BN_free(c);
        BN_free(r);
        BN_free(s);
        BN_free(t);
        BN_free(cx);
        return -1;
    }
    
    /* Combine t and s into proof */
    memcpy(proof, t_bin, t_len);
    memcpy(proof + t_len, s_bin, s_len);
    *proof_size = t_len + s_len;
    
    /* Clean up */
    BN_CTX_free(ctx);
    BN_free(x);
    BN_free(c);
    BN_free(r);
    BN_free(s);
    BN_free(t);
    BN_free(cx);
    
    return 0;
}

int libaura_verify_zkp(uint32_t component_hash,
                      const uint8_t* public_key, size_t public_key_size,
                      const uint8_t* challenge, size_t challenge_size,
                      const uint8_t* proof, size_t proof_size) {
    if (!public_key || public_key_size == 0 ||
        !challenge || challenge_size == 0 ||
        !proof || proof_size < 64) {
        return -1;
    }
    
    /* Initialize cryptographic parameters if needed */
    if (!initialized && initialize_crypto_params() != 0) {
        return -1;
    }
    
    /* Create BN_CTX for calculations */
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        return -1;
    }
    
    /* Extract t and s from proof */
    const unsigned char *t_bin = proof;
    const unsigned char *s_bin = proof + 32;
    
    /* Convert inputs to BIGNUMs */
    BIGNUM *y = BN_bin2bn(public_key, public_key_size, NULL);
    BIGNUM *c = BN_bin2bn(challenge, challenge_size, NULL);
    BIGNUM *t = BN_bin2bn(t_bin, 32, NULL);
    BIGNUM *s = BN_bin2bn(s_bin, 32, NULL);
    
    if (!y || !c || !t || !s) {
        BN_CTX_free(ctx);
        if (y) BN_free(y);
        if (c) BN_free(c);
        if (t) BN_free(t);
        if (s) BN_free(s);
        return -1;
    }
    
    /* Verify equation: g^s == t * y^c (mod p) */
    /* Compute g^s mod p */
    BIGNUM *g_s = BN_new();
    if (!g_s || BN_mod_exp(g_s, g, s, p, ctx) != 1) {
        BN_CTX_free(ctx);
        BN_free(y);
        BN_free(c);
        BN_free(t);
        BN_free(s);
        if (g_s) BN_free(g_s);
        return -1;
    }
    
    /* Compute y^c mod p */
    BIGNUM *y_c = BN_new();
    if (!y_c || BN_mod_exp(y_c, y, c, p, ctx) != 1) {
        BN_CTX_free(ctx);
        BN_free(y);
        BN_free(c);
        BN_free(t);
        BN_free(s);
        BN_free(g_s);
        if (y_c) BN_free(y_c);
        return -1;
    }
    
    /* Compute t * y^c mod p */
    BIGNUM *t_y_c = BN_new();
    if (!t_y_c || BN_mod_mul(t_y_c, t, y_c, p, ctx) != 1) {
        BN_CTX_free(ctx);
        BN_free(y);
        BN_free(c);
        BN_free(t);
        BN_free(s);
        BN_free(g_s);
        BN_free(y_c);
        if (t_y_c) BN_free(t_y_c);
        return -1;
    }
    
    /* Compare g^s and t * y^c */
    int result = BN_cmp(g_s, t_y_c);
    
    /* Clean up */
    BN_CTX_free(ctx);
    BN_free(y);
    BN_free(c);
    BN_free(t);
    BN_free(s);
    BN_free(g_s);
    BN_free(y_c);
    BN_free(t_y_c);
    
    return (result == 0) ? 0 : -1;
}

int libaura_update_container_state(libaura_container_state_t* state,
                                  const char* operation_desc,
                                  const void* operation_data,
                                  size_t operation_size) {
    if (!state || !operation_desc || !operation_data || operation_size == 0) {
        return -1;
    }
    
    /* Update transaction ID */
    state->transaction_id++;
    
    /* Update timestamp */
    state->timestamp = (uint64_t)time(NULL);
    
    /* Calculate hash of operation */
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, operation_desc, strlen(operation_desc));
    SHA256_Update(&ctx, operation_data, operation_size);
    SHA256_Update(&ctx, &state->transaction_id, sizeof(state->transaction_id));
    SHA256_Update(&ctx, &state->timestamp, sizeof(state->timestamp));
    SHA256_Final(state->last_operation_hash, &ctx);
    
    /* Update state hash */
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, state->state_hash, sizeof(state->state_hash));
    SHA256_Update(&ctx, state->last_operation_hash, sizeof(state->last_operation_hash));
    SHA256_Final(state->state_hash, &ctx);
    
    return 0;
}

uint32_t libaura_generate_component_hash(const void* component, size_t size) {
    if (!component || size == 0) {
        return 0;
    }
    
    /* Calculate SHA-256 hash */
    uint8_t hash[32];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, component, size);
    SHA256_Final(hash, &ctx);
    
    /* Extract 32-bit hash from first 4 bytes */
    uint32_t component_hash = ((uint32_t)hash[0] << 24) |
                             ((uint32_t)hash[1] << 16) |
                             ((uint32_t)hash[2] << 8) |
                             ((uint32_t)hash[3]);
    
    return component_hash;
}

int libaura_combine_component_chain(const uint32_t* components, size_t count, uint8_t* chain_hash) {
    if (!components || count == 0 || !chain_hash) {
        return -1;
    }
    
    /* Calculate combined hash of all components */
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    
    /* Add each component hash to the chain */
    for (size_t i = 0; i < count; i++) {
        SHA256_Update(&ctx, &components[i], sizeof(uint32_t));
    }
    
    /* Finalize hash */
    SHA256_Final(chain_hash, &ctx);
    
    return 0;
}

int libaura_verify_component_chain(const uint8_t* chain_hash, const uint32_t* components, size_t count) {
    if (!chain_hash || !components || count == 0) {
        return -1;
    }
    
    /* Calculate chain hash */
    uint8_t calculated_hash[32];
    libaura_combine_component_chain(components, count, calculated_hash);
    
    /* Compare with provided hash */
    return (memcmp(chain_hash, calculated_hash, 32) == 0) ? 0 : -1;
}