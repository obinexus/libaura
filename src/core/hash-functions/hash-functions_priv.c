/**
 * @file hash-functions_priv.c
 * @brief Private implementation of LibAura hash functions
 * 
 * Implements internal transformation functions with entropy distribution
 * and recursive digestion to ensure balanced entropy in the output.
 * 
 * Copyright © 2025 OBINexus Computing - Computing from the Heart
 */

#include "libaura/core/hash-functions/hash-functions_public.h"
#include "libaura/core/hash-functions/hash-functions_types.h"
#include "libaura/core/hash-functions/hash-functions_constants.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <math.h>

/* Internal state structure */
typedef struct {
    uint64_t state[8];
    uint64_t byte_count;
    uint8_t buffer[LIBAURA_BLOCK_SIZE];
    size_t buffer_size;
} libaura_internal_state_t;

/* Forward declarations */
static void libaura_transform_block(libaura_internal_state_t* state, const uint8_t* block);
static void libaura_distribute_entropy(uint8_t* digest, size_t size);
static double libaura_calculate_entropy(const uint8_t* data, size_t size);

/* Initialize internal state */
static void libaura_init_state(libaura_internal_state_t* state) {
    memset(state, 0, sizeof(libaura_internal_state_t));
    /* Initialize with magic constants for balanced entropy */
    for (int i = 0; i < 8; i++) {
        state->state[i] = LIBAURA_HASH_MAGIC[i];
    }
}

/* Process a single block */
static void libaura_transform_block(libaura_internal_state_t* state, const uint8_t* block) {
    uint64_t temp[8];
    uint64_t a, b, c, d, e, f, g, h;
    uint64_t w[80];
    
    /* Initialize working variables with current state */
    memcpy(temp, state->state, sizeof(temp));
    a = temp[0]; b = temp[1]; c = temp[2]; d = temp[3];
    e = temp[4]; f = temp[5]; g = temp[6]; h = temp[7];
    
    /* Prepare the message schedule */
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint64_t)block[i*8] << 56) | ((uint64_t)block[i*8+1] << 48) |
               ((uint64_t)block[i*8+2] << 40) | ((uint64_t)block[i*8+3] << 32) |
               ((uint64_t)block[i*8+4] << 24) | ((uint64_t)block[i*8+5] << 16) |
               ((uint64_t)block[i*8+6] << 8) | ((uint64_t)block[i*8+7]);
    }
    
    for (int i = 16; i < 80; i++) {
        uint64_t s0 = (w[i-15] >> 1) ^ (w[i-15] << 63) ^ (w[i-15] >> 8) ^ (w[i-15] << 56) ^ (w[i-15] >> 7);
        uint64_t s1 = (w[i-2] >> 19) ^ (w[i-2] << 45) ^ (w[i-2] >> 61) ^ (w[i-2] << 3) ^ (w[i-2] >> 6);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
        
        /* Entropy distribution within message schedule */
        if (i % 4 == 0) {
            uint8_t entropy_byte = (uint8_t)((w[i] ^ w[i-1] ^ w[i-2] ^ w[i-3]) & 0xFF);
            w[i] ^= ((uint64_t)entropy_byte << 32);
        }
    }
    
    /* Main loop - apply transformation rounds with entropy spreading */
    for (int i = 0; i < 80; i++) {
        uint64_t s1 = (e >> 14) ^ (e << 50) ^ (e >> 18) ^ (e << 46) ^ (e >> 41) ^ (e << 23);
        uint64_t ch = (e & f) ^ ((~e) & g);
        uint64_t temp1 = h + s1 + ch + LIBAURA_HASH_MAGIC[i % 8] + w[i];
        uint64_t s0 = (a >> 28) ^ (a << 36) ^ (a >> 34) ^ (a << 30) ^ (a >> 39) ^ (a << 25);
        uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint64_t temp2 = s0 + maj;
        
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
        
        /* Apply entropy distribution during transformation */
        if (i % 10 == 0) {
            a ^= ((a ^ b) & 0x0101010101010101ULL);
            e ^= ((e ^ f) & 0x0101010101010101ULL);
        }
    }
    
    /* Update state with transformed values */
    state->state[0] += a;
    state->state[1] += b;
    state->state[2] += c;
    state->state[3] += d;
    state->state[4] += e;
    state->state[5] += f;
    state->state[6] += g;
    state->state[7] += h;
    
    /* Final entropy spreading within state */
    uint64_t entropy_marker = state->state[0] ^ state->state[1] ^ 
                             state->state[2] ^ state->state[3] ^
                             state->state[4] ^ state->state[5] ^
                             state->state[6] ^ state->state[7];
                             
    for (int i = 0; i < 8; i++) {
        state->state[i] ^= (entropy_marker & 0x0101010101010101ULL);
        entropy_marker = (entropy_marker << 1) | (entropy_marker >> 63);
    }
}

/* Distribute entropy across digest to ensure even distribution */
static void libaura_distribute_entropy(uint8_t* digest, size_t size) {
    if (!digest || size == 0) {
        return;
    }
    
    /* Calculate initial entropy map */
    uint8_t frequency[256] = {0};
    for (size_t i = 0; i < size; i++) {
        frequency[digest[i]]++;
    }
    
    /* Determine entropy distribution */
    uint8_t min_freq = 255, max_freq = 0;
    for (int i = 0; i < 256; i++) {
        if (frequency[i] > 0) {
            if (frequency[i] < min_freq) min_freq = frequency[i];
            if (frequency[i] > max_freq) max_freq = frequency[i];
        }
    }
    
    /* If entropy is already well distributed, return */
    if (max_freq - min_freq <= 2) {
        return;
    }
    
    /* Apply entropy redistribution */
    uint8_t temp[size];
    memcpy(temp, digest, size);
    
    for (size_t i = 0; i < size; i++) {
        /* Apply a reversible transformation based on position and neighbors */
        uint8_t prev = (i > 0) ? temp[i-1] : temp[size-1];
        uint8_t next = (i < size-1) ? temp[i+1] : temp[0];
        
        /* XOR with neighbors to spread influence */
        digest[i] = temp[i] ^ ((prev & 0x0F) | ((next & 0x0F) << 4));
        
        /* Apply position-dependent rotation to avoid patterns */
        uint8_t rotation = (i % 7) + 1;
        digest[i] = (digest[i] << rotation) | (digest[i] >> (8 - rotation));
    }
    
    /* Apply final balancing pass */
    uint8_t checksum = 0;
    for (size_t i = 0; i < size; i++) {
        checksum ^= digest[i];
    }
    
    for (size_t i = 0; i < size; i++) {
        if (i % 5 == 0) {
            digest[i] ^= (checksum & 0x0F);
        } else if (i % 5 == 1) {
            digest[i] ^= ((checksum & 0xF0) >> 4);
        }
    }
}

/* Calculate Shannon entropy of data */
static double libaura_calculate_entropy(const uint8_t* data, size_t size) {
    if (!data || size == 0) {
        return 0.0;
    }
    
    /* Count byte frequencies */
    unsigned int frequencies[256] = {0};
    for (size_t i = 0; i < size; i++) {
        frequencies[data[i]]++;
    }
    
    /* Calculate Shannon entropy */
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (frequencies[i] > 0) {
            double probability = (double)frequencies[i] / size;
            entropy -= probability * log2(probability);
        }
    }
    
    return entropy;
}

/* Internal function to convert raw digest to final output based on digest size */
static void libaura_finalize_digest(const libaura_internal_state_t* state, 
                                  uint8_t* digest, libaura_digest_size_t digest_size) {
    uint8_t full_digest[64];
    
    /* First, convert state to bytes */
    for (int i = 0; i < 8; i++) {
        full_digest[i*8]   = (uint8_t)(state->state[i] >> 56);
        full_digest[i*8+1] = (uint8_t)(state->state[i] >> 48);
        full_digest[i*8+2] = (uint8_t)(state->state[i] >> 40);
        full_digest[i*8+3] = (uint8_t)(state->state[i] >> 32);
        full_digest[i*8+4] = (uint8_t)(state->state[i] >> 24);
        full_digest[i*8+5] = (uint8_t)(state->state[i] >> 16);
        full_digest[i*8+6] = (uint8_t)(state->state[i] >> 8);
        full_digest[i*8+7] = (uint8_t)(state->state[i]);
    }
    
    /* Apply entropy distribution to full digest */
    libaura_distribute_entropy(full_digest, 64);
    
    /* Copy appropriate sized output */
    size_t digest_bytes = 0;
    switch (digest_size) {
        case LIBAURA_DIGEST_64:
            digest_bytes = LIBAURA_DIGEST_SIZE_64;
            break;
        case LIBAURA_DIGEST_256:
            digest_bytes = LIBAURA_DIGEST_SIZE_256;
            break;
        case LIBAURA_DIGEST_512:
            digest_bytes = LIBAURA_DIGEST_SIZE_512;
            break;
        default:
            digest_bytes = LIBAURA_DIGEST_SIZE_256;
            break;
    }
    
    /* If digest size is less than full, use a folding technique */
    if (digest_bytes < 64) {
        for (size_t i = 0; i < digest_bytes; i++) {
            digest[i] = full_digest[i] ^ full_digest[i + digest_bytes];
            if (digest_bytes == LIBAURA_DIGEST_SIZE_64 && i < 4) {
                digest[i] ^= full_digest[i + 2*digest_bytes] ^ full_digest[i + 3*digest_bytes];
            }
        }
    } else {
        memcpy(digest, full_digest, digest_bytes);
    }
    
    /* Final entropy redistribution for output size */
    libaura_distribute_entropy(digest, digest_bytes);
}

/* Exported functions for use by public.c */
void libaura_hash_process_blocks(libaura_hash_context_t* context, const uint8_t* data, size_t size);
void libaura_hash_finalize_internal(libaura_hash_context_t* context, uint8_t* digest);
uint8_t libaura_calculate_entropy_score(const uint8_t* data, size_t size);

/* Process full blocks of data */
void libaura_hash_process_blocks(libaura_hash_context_t* context, const uint8_t* data, size_t size) {
    libaura_internal_state_t state;
    libaura_init_state(&state);
    
    /* Process complete blocks */
    size_t offset = 0;
    while (offset + LIBAURA_BLOCK_SIZE <= size) {
        libaura_transform_block(&state, data + offset);
        offset += LIBAURA_BLOCK_SIZE;
        state.byte_count += LIBAURA_BLOCK_SIZE;
    }
    
    /* Store remaining data in buffer */
    if (offset < size) {
        size_t remaining = size - offset;
        memcpy(state.buffer, data + offset, remaining);
        state.buffer_size = remaining;
    }
    
    /* Copy state back to context */
    memcpy(context->state, &state, sizeof(libaura_internal_state_t));
}

/* Finalize hash computation */
void libaura_hash_finalize_internal(libaura_hash_context_t* context, uint8_t* digest) {
    libaura_internal_state_t state;
    memcpy(&state, context->state, sizeof(libaura_internal_state_t));
    
    /* Add padding similar to SHA-2 */
    uint8_t padded[LIBAURA_BLOCK_SIZE * 2] = {0};
    size_t padded_size = 0;
    
    /* Copy buffer content */
    memcpy(padded, state.buffer, state.buffer_size);
    padded_size = state.buffer_size;
    
    /* Append 1 bit followed by zeros */
    padded[padded_size++] = 0x80;
    
    /* Ensure space for length at the end */
    if (padded_size > LIBAURA_BLOCK_SIZE - 16) {
        /* Fill with zeros */
        while (padded_size < LIBAURA_BLOCK_SIZE) {
            padded[padded_size++] = 0;
        }
        
        /* Process this block */
        libaura_transform_block(&state, padded);
        
        /* Reset for final block */
        padded_size = 0;
    }
    
    /* Fill with zeros until space for length */
    while (padded_size < LIBAURA_BLOCK_SIZE - 16) {
        padded[padded_size++] = 0;
    }
    
    /* Append total length in bits (128 bits / 16 bytes) */
    uint64_t total_bits_hi = 0;
    uint64_t total_bits_lo = state.byte_count * 8;
    
    for (int i = 0; i < 8; i++) {
        padded[padded_size++] = (uint8_t)(total_bits_hi >> (56 - i*8));
    }
    
    for (int i = 0; i < 8; i++) {
        padded[padded_size++] = (uint8_t)(total_bits_lo >> (56 - i*8));
    }
    
    /* Process final block */
    libaura_transform_block(&state, padded);
    
    /* Produce final digest */
    libaura_finalize_digest(&state, digest, context->digest_size);
    
    /* Check entropy and enhance if needed */
    double entropy = libaura_calculate_entropy(digest, 
        context->digest_size == LIBAURA_DIGEST_64 ? 8 : 
        context->digest_size == LIBAURA_DIGEST_256 ? 32 : 64);
    
    /* If entropy is too low, apply additional balancing */
    if (entropy < (context->digest_size == LIBAURA_DIGEST_64 ? 2.5 : 
                  context->digest_size == LIBAURA_DIGEST_256 ? 7.0 : 7.8)) {
        libaura_distribute_entropy(digest, 
            context->digest_size == LIBAURA_DIGEST_64 ? 8 : 
            context->digest_size == LIBAURA_DIGEST_256 ? 32 : 64);
    }
}

/* Calculate entropy score (0-255) */
uint8_t libaura_calculate_entropy_score(const uint8_t* data, size_t size) {
    double entropy = libaura_calculate_entropy(data, size);
    double max_entropy = 8.0; /* Maximum possible entropy for bytes */
    
    /* Scale to 0-255 range */
    double normalized = (entropy / max_entropy) * 255.0;
    
    /* Handle boundary cases */
    if (normalized > 255.0) {
        normalized = 255.0;
    } else if (normalized < 0.0) {
        normalized = 0.0;
    }
    
    return (uint8_t)normalized;
}