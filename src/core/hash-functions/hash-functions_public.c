/**
 * @file hash-functions_public.c
 * @brief Public implementation of LibAura hash functions
 * 
 * Implements the public API for hash function operations, integrating
 * with the component container system and providing configurable hash
 * function behavior.
 * 
 * Copyright © 2025 OBINexus Computing - Computing from the Heart
 */

#include "libaura/core/hash-functions/hash-functions_public.h"
#include "libaura/core/component-container/component-container_public.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include "libaura/core/hash-functions/hash-functions_config.h"

/* Static module state */
static bool s_initialized = false;
static libaura_hash_info_t s_hash_components[3];
static libaura_hash_config_t s_config; /* Global configuration */

/* Initialize the hash functions module */
int libaura_hash_initialize(void) {
    if (s_initialized) {
        return 0; /* Already initialized */
    }
    
    /* Initialize configuration with defaults */
    if (libaura_hash_config_init(&s_config) != 0) {
        return -1;
    }
    
    /* Try to load configuration from default location */
    libaura_hash_config_load(&s_config, s_config.config_file);
    
    /* Setup hash algorithm components based on configuration */
    s_hash_components[0] = (libaura_hash_info_t){
        .name = LIBAURA_HASH_COMPONENT_AURA64,
        .digest_size = LIBAURA_DIGEST_64,
        .min_entropy = s_config.min_entropy_aura64,
        .security_level = 2,
        .description = "Aura64 hash function (8-byte digest)"
    };
    
    s_hash_components[1] = (libaura_hash_info_t){
        .name = LIBAURA_HASH_COMPONENT_AURA256,
        .digest_size = LIBAURA_DIGEST_256,
        .min_entropy = s_config.min_entropy_aura256,
        .security_level = 4,
        .description = "Aura256 hash function (32-byte digest)"
    };
    
    s_hash_components[2] = (libaura_hash_info_t){
        .name = LIBAURA_HASH_COMPONENT_AURA512,
        .digest_size = LIBAURA_DIGEST_512,
        .min_entropy = s_config.min_entropy_aura512,
        .security_level = 5,
        .description = "Aura512 hash function (64-byte digest)"
    };
    
    s_initialized = true;
    return 0;
}

/* Clean up the hash functions module */
void libaura_hash_cleanup(void) {
    /* Clean up configuration */
    libaura_hash_config_cleanup(&s_config);
    
    /* Reset module state */
    s_initialized = false;
}
/* External functions from priv.c */
extern void libaura_hash_process_blocks(libaura_hash_context_t* context, const uint8_t* data, size_t size);
extern void libaura_hash_finalize_internal(libaura_hash_context_t* context, uint8_t* digest);
extern uint8_t libaura_calculate_entropy_score(const uint8_t* data, size_t size);

/* Static module state */
static bool s_initialized = false;
static libaura_hash_info_t s_hash_components[3];

/* Initialize the hash functions module */
int libaura_hash_initialize(void) {
    if (s_initialized) {
        return 0; /* Already initialized */
    }
    
    /* Setup hash algorithm components */
    s_hash_components[0] = (libaura_hash_info_t){
        .name = LIBAURA_HASH_COMPONENT_AURA64,
        .digest_size = LIBAURA_DIGEST_64,
        .min_entropy = 180,
        .security_level = 2,
        .description = "Aura64 hash function (8-byte digest)"
    };
    
    s_hash_components[1] = (libaura_hash_info_t){
        .name = LIBAURA_HASH_COMPONENT_AURA256,
        .digest_size = LIBAURA_DIGEST_256,
        .min_entropy = 210,
        .security_level = 4,
        .description = "Aura256 hash function (32-byte digest)"
    };
    
    s_hash_components[2] = (libaura_hash_info_t){
        .name = LIBAURA_HASH_COMPONENT_AURA512,
        .digest_size = LIBAURA_DIGEST_512,
        .min_entropy = 230,
        .security_level = 5,
        .description = "Aura512 hash function (64-byte digest)"
    };
    
    s_initialized = true;
    return 0;
}

/* Clean up the hash functions module */
void libaura_hash_cleanup(void) {
    /* Reset module state */
    s_initialized = false;
}

/* Register hash function components with the container */
int libaura_hash_register_components(void* registry_context) {
    if (!s_initialized) {
        libaura_hash_initialize();
    }
    
    if (!registry_context) {
        return -1;
    }
    
    libaura_container_context_t* context = (libaura_container_context_t*)registry_context;
    
    /* Create component interfaces for hash functions */
    for (int i = 0; i < 3; i++) {
        libaura_component_interface_t component = {
            .name = s_hash_components[i].name,
            .create = NULL,  /* Hash functions are stateless, no instance creation */
            .destroy = NULL,
            .get_interface = NULL,
            .verify = NULL,
            .hash = 0,       /* Will be calculated during registration */
            .entropy_distribution = (uint8_t)(s_hash_components[i].min_entropy)
        };
        
        /* Calculate component hash */
        uint8_t digest[32];
        SHA256((const unsigned char*)&component, sizeof(component) - sizeof(uint32_t), digest);
        component.hash = ((uint32_t)digest[0] << 24) | ((uint32_t)digest[1] << 16) |
                        ((uint32_t)digest[2] << 8) | ((uint32_t)digest[3]);
        
        /* Register with container */
        if (libaura_container_register_component(context, &component) != 0) {
            return -1;
        }
    }
    
    return 0;
}

/* Initialize a hash context */
int libaura_hash_init(libaura_hash_context_t* context, libaura_digest_size_t digest_size) {
    if (!context) {
        return LIBAURA_HASH_ERROR_INVALID_PARAM;
    }
    
    /* Initialize context */
    memset(context, 0, sizeof(libaura_hash_context_t));
    context->digest_size = digest_size;
    
    /* Set transformation rounds based on digest size */
    switch (digest_size) {
        case LIBAURA_DIGEST_64:
            context->rounds = LIBAURA_ROUNDS_AURA64;
            break;
        case LIBAURA_DIGEST_256:
            context->rounds = LIBAURA_ROUNDS_AURA256;
            break;
        case LIBAURA_DIGEST_512:
            context->rounds = LIBAURA_ROUNDS_AURA512;
            break;
        default:
            return LIBAURA_HASH_ERROR_INVALID_PARAM;
    }
    
    /* Clear entropy map */
    memset(context->entropy_map, 0, sizeof(context->entropy_map));
    
    return LIBAURA_HASH_SUCCESS;
}

/* Update hash with data */
int libaura_hash_update(libaura_hash_context_t* context, const void* data, size_t size) {
    if (!context || !data) {
        return LIBAURA_HASH_ERROR_INVALID_PARAM;
    }
    
    /* Process data */
    const uint8_t* input = (const uint8_t*)data;
    
    /* Process existing buffer + new data if it completes a block */
    if (context->buffer_size + size >= LIBAURA_BLOCK_SIZE) {
        /* Fill the existing buffer */
        size_t needed = LIBAURA_BLOCK_SIZE - context->buffer_size;
        memcpy(context->buffer + context->buffer_size, input, needed);
        
        /* Process the complete block */
        libaura_hash_process_blocks(context, context->buffer, LIBAURA_BLOCK_SIZE);
        
        /* Update counters */
        input += needed;
        size -= needed;
        context->processed_bytes += LIBAURA_BLOCK_SIZE;
        context->buffer_size = 0;
    }
    
    /* Process complete blocks from input */
    size_t num_blocks = size / LIBAURA_BLOCK_SIZE;
    if (num_blocks > 0) {
        size_t block_bytes = num_blocks * LIBAURA_BLOCK_SIZE;
        libaura_hash_process_blocks(context, input, block_bytes);
        input += block_bytes;
        size -= block_bytes;
        context->processed_bytes += block_bytes;
    }
    
    /* Store remaining data in buffer */
    if (size > 0) {
        memcpy(context->buffer + context->buffer_size, input, size);
        context->buffer_size += size;
    }
    
    return LIBAURA_HASH_SUCCESS;
}

/* Finalize hash and output digest */
int libaura_hash_final(libaura_hash_context_t* context, uint8_t* digest) {
    if (!context || !digest) {
        return LIBAURA_HASH_ERROR_INVALID_PARAM;
    }
    
    /* Determine digest size in bytes */
    size_t digest_size = 0;
    switch (context->digest_size) {
        case LIBAURA_DIGEST_64:
            digest_size = LIBAURA_DIGEST_SIZE_64;
            break;
        case LIBAURA_DIGEST_256:
            digest_size = LIBAURA_DIGEST_SIZE_256;
            break;
        case LIBAURA_DIGEST_512:
            digest_size = LIBAURA_DIGEST_SIZE_512;
            break;
        default:
            return LIBAURA_HASH_ERROR_INVALID_PARAM;
    }
    
    /* Finalize hash computation */
    libaura_hash_finalize_internal(context, digest);
    
    /* Check entropy distribution */
    uint8_t entropy_score = libaura_calculate_entropy_score(digest, digest_size);
    
    /* Ensure entropy meets minimum threshold */
    uint8_t min_threshold = 0;
    switch (context->digest_size) {
        case LIBAURA_DIGEST_64:
            min_threshold = s_hash_components[0].min_entropy;
            break;
        case LIBAURA_DIGEST_256:
            min_threshold = s_hash_components[1].min_entropy;
            break;
        case LIBAURA_DIGEST_512:
            min_threshold = s_hash_components[2].min_entropy;
            break;
    }
    
    if (entropy_score < min_threshold) {
        return LIBAURA_HASH_ERROR_ENTROPY;
    }
    
    return LIBAURA_HASH_SUCCESS;
}

/* Compute hash digest in one operation */
int libaura_hash_compute(int algorithm, const void* data, size_t size, 
                        uint8_t* digest, size_t digest_size) {
    if (!data || !digest) {
        return LIBAURA_HASH_ERROR_INVALID_PARAM;
    }
    
    /* Validate algorithm and digest size compatibility */
    libaura_digest_size_t digest_type;
    size_t required_size;
    
    switch (algorithm) {
        case LIBAURA_HASH_AURA64:
            digest_type = LIBAURA_DIGEST_64;
            required_size = LIBAURA_DIGEST_SIZE_64;
            break;
        case LIBAURA_HASH_AURA256:
            digest_type = LIBAURA_DIGEST_256;
            required_size = LIBAURA_DIGEST_SIZE_256;
            break;
        case LIBAURA_HASH_AURA512:
            digest_type = LIBAURA_DIGEST_512;
            required_size = LIBAURA_DIGEST_SIZE_512;
            break;
        default:
            return LIBAURA_HASH_ERROR_INVALID_PARAM;
    }
    
    if (digest_size < required_size) {
        return LIBAURA_HASH_ERROR_INVALID_PARAM;
    }
    
    /* Initialize context */
    libaura_hash_context_t context;
    if (libaura_hash_init(&context, digest_type) != LIBAURA_HASH_SUCCESS) {
        return LIBAURA_HASH_ERROR;
    }
    
    /* Update with data */
    if (libaura_hash_update(&context, data, size) != LIBAURA_HASH_SUCCESS) {
        return LIBAURA_HASH_ERROR;
    }
    
    /* Finalize */
    return libaura_hash_final(&context, digest);
}

/* Computes Aura64 hash */
int libaura_hash_aura64(const void* data, size_t size, uint8_t digest[LIBAURA_DIGEST_SIZE_64]) {
    return libaura_hash_compute(LIBAURA_HASH_AURA64, data, size, digest, LIBAURA_DIGEST_SIZE_64);
}

/* Computes Aura256 hash */
int libaura_hash_aura256(const void* data, size_t size, uint8_t digest[LIBAURA_DIGEST_SIZE_256]) {
    return libaura_hash_compute(LIBAURA_HASH_AURA256, data, size, digest, LIBAURA_DIGEST_SIZE_256);
}

/* Computes Aura512 hash */
int libaura_hash_aura512(const void* data, size_t size, uint8_t digest[LIBAURA_DIGEST_SIZE_512]) {
    return libaura_hash_compute(LIBAURA_HASH_AURA512, data, size, digest, LIBAURA_DIGEST_SIZE_512);
}

/* Initialize HMAC context */
int libaura_hmac_init(libaura_hmac_context_t* context, const uint8_t* key, 
                     size_t key_length, libaura_digest_size_t digest_size) {
    if (!context || !key) {
        return LIBAURA_HASH_ERROR_INVALID_PARAM;
    }
    
    /* Initialize HMAC context */
    memset(context, 0, sizeof(libaura_hmac_context_t));
    
    /* Initialize hash context */
    if (libaura_hash_init(&context->hash_ctx, digest_size) != LIBAURA_HASH_SUCCESS) {
        return LIBAURA_HASH_ERROR;
    }
    
    /* Store key */
    if (key_length > sizeof(context->key)) {
        /* If key is too long, hash it */
        if (libaura_hash_compute(
                digest_size == LIBAURA_DIGEST_64 ? LIBAURA_HASH_AURA64 :
                digest_size == LIBAURA_DIGEST_256 ? LIBAURA_HASH_AURA256 : LIBAURA_HASH_AURA512,
                key, key_length, context->key, sizeof(context->key)) != LIBAURA_HASH_SUCCESS) {
            return LIBAURA_HASH_ERROR;
        }
        context->key_length = digest_size == LIBAURA_DIGEST_64 ? LIBAURA_DIGEST_SIZE_64 :
                            digest_size == LIBAURA_DIGEST_256 ? LIBAURA_DIGEST_SIZE_256 : LIBAURA_DIGEST_SIZE_512;
    } else {
        memcpy(context->key, key, key_length);
        context->key_length = key_length;
    }
    
    /* Create inner padded key */
    uint8_t ipad[LIBAURA_BLOCK_SIZE];
    memset(ipad, 0x36, sizeof(ipad));
    for (size_t i = 0; i < context->key_length; i++) {
        ipad[i] ^= context->key[i];
    }
    
    /* Initialize hash with inner padding */
    if (libaura_hash_update(&context->hash_ctx, ipad, sizeof(ipad)) != LIBAURA_HASH_SUCCESS) {
        return LIBAURA_HASH_ERROR;
    }
    
    context->initialized = true;
    return LIBAURA_HASH_SUCCESS;
}

/* Update HMAC with data */
int libaura_hmac_update(libaura_hmac_context_t* context, const void* data, size_t size) {
    if (!context || !data || !context->initialized) {
        return LIBAURA_HASH_ERROR_INVALID_PARAM;
    }
    
    /* Update hash with data */
    return libaura_hash_update(&context->hash_ctx, data, size);
}

/* Finalize HMAC and output digest */
int libaura_hmac_final(libaura_hmac_context_t* context, uint8_t* digest) {
    if (!context || !digest || !context->initialized) {
        return LIBAURA_HASH_ERROR_INVALID_PARAM;
    }
    
    /* Determine digest size in bytes */
    size_t digest_size = 0;
    int algorithm = 0;
    
    switch (context->hash_ctx.digest_size) {
        case LIBAURA_DIGEST_64:
            digest_size = LIBAURA_DIGEST_SIZE_64;
            algorithm = LIBAURA_HASH_AURA64;
            break;
        case LIBAURA_DIGEST_256:
            digest_size = LIBAURA_DIGEST_SIZE_256;
            algorithm = LIBAURA_HASH_AURA256;
            break;
        case LIBAURA_DIGEST_512:
            digest_size = LIBAURA_DIGEST_SIZE_512;
            algorithm = LIBAURA_HASH_AURA512;
            break;
        default:
            return LIBAURA_HASH_ERROR_INVALID_PARAM;
    }
    
    /* Finalize inner hash */
    uint8_t inner_hash[LIBAURA_DIGEST_SIZE_512];
    if (libaura_hash_final(&context->hash_ctx, inner_hash) != LIBAURA_HASH_SUCCESS) {
        return LIBAURA_HASH_ERROR;
    }
    
    /* Create outer padded key */
    uint8_t opad[LIBAURA_BLOCK_SIZE];
    memset(opad, 0x5C, sizeof(opad));
    for (size_t i = 0; i < context->key_length; i++) {
        opad[i] ^= context->key[i];
    }
    
    /* Compute outer hash */
    libaura_hash_context_t outer_ctx;
    if (libaura_hash_init(&outer_ctx, context->hash_ctx.digest_size) != LIBAURA_HASH_SUCCESS) {
        return LIBAURA_HASH_ERROR;
    }
    
    if (libaura_hash_update(&outer_ctx, opad, sizeof(opad)) != LIBAURA_HASH_SUCCESS ||
        libaura_hash_update(&outer_ctx, inner_hash, digest_size) != LIBAURA_HASH_SUCCESS ||
        libaura_hash_final(&outer_ctx, digest) != LIBAURA_HASH_SUCCESS) {
        return LIBAURA_HASH_ERROR;
    }
    
    return LIBAURA_HASH_SUCCESS;
}

/* Compute HMAC in one operation */
int libaura_hmac_compute(const uint8_t* key, size_t key_length,
                        const void* data, size_t size,
                        uint8_t* digest, size_t digest_size) {
    if (!key || !data || !digest) {
        return LIBAURA_HASH_ERROR_INVALID_PARAM;
    }
    
    /* Determine digest type */
    libaura_digest_size_t digest_type;
    size_t required_size;
    
    if (digest_size >= LIBAURA_DIGEST_SIZE_512) {
        digest_type = LIBAURA_DIGEST_512;
        required_size = LIBAURA_DIGEST_SIZE_512;
    } else if (digest_size >= LIBAURA_DIGEST_SIZE_256) {
        digest_type = LIBAURA_DIGEST_256;
        required_size = LIBAURA_DIGEST_SIZE_256;
    } else if (digest_size >= LIBAURA_DIGEST_SIZE_64) {
        digest_type = LIBAURA_DIGEST_64;
        required_size = LIBAURA_DIGEST_SIZE_64;
    } else {
        return LIBAURA_HASH_ERROR_INVALID_PARAM;
    }
    
    /* Initialize HMAC context */
    libaura_hmac_context_t context;
    if (libaura_hmac_init(&context, key, key_length, digest_type) != LIBAURA_HASH_SUCCESS) {
        return LIBAURA_HASH_ERROR;
    }
    
    /* Update with data */
    if (libaura_hmac_update(&context, data, size) != LIBAURA_HASH_SUCCESS) {
        return LIBAURA_HASH_ERROR;
    }
    
    /* Finalize */
    return libaura_hmac_final(&context, digest);
}

/* Derives a cryptographic key using HMAC */
int libaura_hmac_derive_key(const uint8_t* private_key, size_t private_key_len,
                          const uint8_t* public_key, size_t public_key_len,
                          uint8_t* derived_key, size_t key_size) {
    if (!private_key || !public_key || !derived_key) {
        return LIBAURA_HASH_ERROR_INVALID_PARAM;
    }
    
    /* Following Kderived = HMACxA(yA) principle from formal proof */
    return libaura_hmac_compute(private_key, private_key_len,
                               public_key, public_key_len,
                               derived_key, key_size);
}

/* Create an Aura ID file (.auraid) */
int libaura_hash_create_id_file(const void* identity_data, size_t identity_size,
                              const char* output_file) {
    if (!identity_data || !output_file) {
        return LIBAURA_HASH_ERROR_INVALID_PARAM;
    }
    
    /* Generate a random salt */
    uint8_t salt[16];
    if (RAND_bytes(salt, sizeof(salt)) != 1) {
        return LIBAURA_HASH_ERROR;
    }
    
    /* Calculate hash of identity + salt */
    uint8_t hash[LIBAURA_DIGEST_SIZE_256];
    
    /* Create combined buffer */
    uint8_t* combined = malloc(identity_size + sizeof(salt));
    if (!combined) {
        return LIBAURA_HASH_ERROR_MEMORY;
    }
    
    memcpy(combined, salt, sizeof(salt));
    memcpy(combined + sizeof(salt), identity_data, identity_size);
    
    /* Calculate hash */
    if (libaura_hash_aura256(combined, identity_size + sizeof(salt), hash) != LIBAURA_HASH_SUCCESS) {
        free(combined);
        return LIBAURA_HASH_ERROR;
    }
    
    free(combined);
    
    /* Split hash into ID and key parts */
    uint8_t id_part[16];
    uint8_t key_part[16];
    
    memcpy(id_part, hash, sizeof(id_part));
    memcpy(key_part, hash + sizeof(id_part), sizeof(key_part));
    
    /* Create ID file format */
    struct {
        uint32_t magic;        /* 'AURA' */
        uint32_t version;      /* 1 */
        uint64_t timestamp;    /* Creation time */
        uint8_t id_hash[16];   /* ID part of hash */
        uint8_t salt[16];      /* Salt */
        uint8_t reserved[16];  /* Reserved for future use */
    } id_file = {
        .magic = 0x41555241,   /* 'AURA' */
        .version = 1,
        .timestamp = (uint64_t)time(NULL),
    };
    
    memcpy(id_file.id_hash, id_part, sizeof(id_file.id_hash));
    memcpy(id_file.salt, salt, sizeof(id_file.salt));
    memset(id_file.reserved, 0, sizeof(id_file.reserved));
    
    /* Write to file */
    FILE* file = fopen(output_file, "wb");
    if (!file) {
        return LIBAURA_HASH_ERROR;
    }
    
    if (fwrite(&id_file, sizeof(id_file), 1, file) != 1) {
        fclose(file);
        return LIBAURA_HASH_ERROR;
    }
    
    fclose(file);
    return LIBAURA_HASH_SUCCESS;
}

/* Create an Aura key file (.auraid.key) */
int libaura_hash_create_key_file(const void* identity_data, size_t identity_size,
                               const char* output_file) {
    if (!identity_data || !output_file) {
        return LIBAURA_HASH_ERROR_INVALID_PARAM;
    }
    
    /* Calculate hash of identity */
    uint8_t hash[LIBAURA_DIGEST_SIZE_256];
    if (libaura_hash_aura256(identity_data, identity_size, hash) != LIBAURA_HASH_SUCCESS) {
        return LIBAURA_HASH_ERROR;
    }
    
    /* Split hash into ID and key parts */
    uint8_t id_part[16];
    uint8_t key_part[16];
    
    memcpy(id_part, hash, sizeof(id_part));
    memcpy(key_part, hash + sizeof(id_part), sizeof(key_part));
    
    /* Create key file format */
    struct {
        uint32_t magic;        /* 'KEYA' */
        uint32_t version;      /* 1 */
        uint64_t timestamp;    /* Creation time */
        uint64_t expiration;   /* Expiration time (0 = never) */
        uint8_t key_hash[16];  /* Key part of hash */
        uint8_t reserved[16];  /* Reserved for future use */
    } key_file = {
        .magic = 0x4B455941,   /* 'KEYA' */
        .version = 1,
        .timestamp = (uint64_t)time(NULL),
        .expiration = 0,       /* Never expire */
    };
    
    memcpy(key_file.key_hash, key_part, sizeof(key_file.key_hash));
    memset(key_file.reserved, 0, sizeof(key_file.reserved));
    
    /* Write to file */
    FILE* file = fopen(output_file, "wb");
    if (!file) {
        return LIBAURA_HASH_ERROR;
    }
    
    if (fwrite(&key_file, sizeof(key_file), 1, file) != 1) {
        fclose(file);
        return LIBAURA_HASH_ERROR;
    }
    
    fclose(file);
    return LIBAURA_HASH_SUCCESS;
}

/* Verify an Aura ID file against identity data */
int libaura_hash_verify_id(const char* id_file, const char* key_file,
                         const void* identity_data, size_t identity_size) {
    if (!id_file || !key_file || !identity_data) {
        return LIBAURA_HASH_ERROR_INVALID_PARAM;
    }
    
    /* Read ID file */
    struct {
        uint32_t magic;        /* 'AURA' */
        uint32_t version;      /* 1 */
        uint64_t timestamp;    /* Creation time */
        uint8_t id_hash[16];   /* ID part of hash */
        uint8_t salt[16];      /* Salt */
        uint8_t reserved[16];  /* Reserved for future use */
    } id_data;
    
    FILE* file = fopen(id_file, "rb");
    if (!file) {
        return LIBAURA_HASH_ERROR;
    }
    
    if (fread(&id_data, sizeof(id_data), 1, file) != 1 ||
        id_data.magic != 0x41555241) {
        fclose(file);
        return LIBAURA_HASH_ERROR;
    }
    
    fclose(file);
    
    /* Read key file */
    struct {
        uint32_t magic;        /* 'KEYA' */
        uint32_t version;      /* 1 */
        uint64_t timestamp;    /* Creation time */
        uint64_t expiration;   /* Expiration time (0 = never) */
        uint8_t key_hash[16];  /* Key part of hash */
        uint8_t reserved[16];  /* Reserved for future use */
    } key_data;
    
    file = fopen(key_file, "rb");
    if (!file) {
        return LIBAURA_HASH_ERROR;
    }
    
    if (fread(&key_data, sizeof(key_data), 1, file) != 1 ||
        key_data.magic != 0x4B455941) {
        fclose(file);
        return LIBAURA_HASH_ERROR;
    }
    
    fclose(file);
    
    /* Check expiration */
    uint64_t current_time = (uint64_t)time(NULL);
    if (key_data.expiration > 0 && current_time > key_data.expiration) {
        return LIBAURA_HASH_ERROR_TAMPERED;
    }
    
    /* Recalculate hash with salt */
    uint8_t* combined = malloc(identity_size + sizeof(id_data.salt));
    if (!combined) {
        return LIBAURA_HASH_ERROR_MEMORY;
    }
    
    memcpy(combined, id_data.salt, sizeof(id_data.salt));
    memcpy(combined + sizeof(id_data.salt), identity_data, identity_size);
    
    uint8_t hash[LIBAURA_DIGEST_SIZE_256];
    if (libaura_hash_aura256(combined, identity_size + sizeof(id_data.salt), hash) != LIBAURA_HASH_SUCCESS) {
        free(combined);
        return LIBAURA_HASH_ERROR;
    }
    
    free(combined);
    
    /* Split calculated hash */
    uint8_t id_part[16];
    uint8_t key_part[16];
    
    memcpy(id_part, hash, sizeof(id_part));
    memcpy(key_part, hash + sizeof(id_part), sizeof(key_part));
    
    /* Compare with stored values */
    if (memcmp(id_part, id_data.id_hash, sizeof(id_part)) != 0 ||
        memcmp(key_part, key_data.key_hash, sizeof(key_part)) != 0) {
        return LIBAURA_HASH_ERROR_TAMPERED;
    }
    
    return LIBAURA_HASH_SUCCESS;
}

/* Check entropy distribution of data */
uint8_t libaura_hash_check_entropy(const void* data, size_t size) {
    if (!data || size == 0) {
        return 0;
    }
    
    return libaura_calculate_entropy_score((const uint8_t*)data, size);
}

/* Get error message for hash result code */
const char* libaura_hash_get_error_message(libaura_hash_result_t result) {
    switch (result) {
        case LIBAURA_HASH_VALID:
            return "Hash verification successful";
        case LIBAURA_HASH_INVALID:
            return "Hash mismatch";
        case LIBAURA_HASH_ERROR:
            return "Error during hash verification";
        case LIBAURA_HASH_ENTROPY_LOW:
            return "Insufficient entropy distribution in hash";
        case LIBAURA_HASH_TAMPERED:
            return "Evidence of tampering detected";
        default:
            return "Unknown hash result code";
    }
}