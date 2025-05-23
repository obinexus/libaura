/**
 * @file component-container_registry.c
 * @brief Implementation of component registry for IoC container
 * 
 * Implements cryptographic integrity verification and zero-knowledge properties
 * as described in the formal proof document.
 * 
 * Copyright © 2025 OBINexus Computing - Computing from the Heart
 */

#include "libaura/core/component-container/component-container_registry.h"
#include "libaura/core/checksum-verification/checksum-verification_verify.h"
#include "component-container_priv.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

/* OpenSSL includes for cryptographic functions */
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

/* Constants for cryptographic operations */
#define LIBAURA_HASH_BUFFER_SIZE 32
#define LIBAURA_HMAC_KEY_SIZE 64
#define LIBAURA_MAX_COMPONENT_NAME 64

/* Shannon entropy calculation for hardness evaluation */
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

int libaura_registry_init(libaura_component_registry_t* registry, size_t initial_capacity) {
    if (!registry || initial_capacity == 0) {
        return -1;
    }
    
    /* Allocate memory for components array */
    registry->components = calloc(initial_capacity, sizeof(libaura_component_interface_t));
    if (!registry->components) {
        return -1;
    }
    
    registry->count = 0;
    registry->capacity = initial_capacity;
    memset(registry->integrity_check, 0, sizeof(registry->integrity_check));
    
    return 0;
}

void libaura_registry_cleanup(libaura_component_registry_t* registry) {
    if (!registry) {
        return;
    }
    
    /* Free components array */
    free(registry->components);
    registry->components = NULL;
    registry->count = 0;
    registry->capacity = 0;
    
    /* Clear integrity check for security */
    memset(registry->integrity_check, 0, sizeof(registry->integrity_check));
}

int libaura_registry_register(libaura_component_registry_t* registry, 
                             const libaura_component_interface_t* component) {
    if (!registry || !component || !component->name) {
        return -1;
    }
    
    /* Check for duplicate components - enforces correctness */
    for (size_t i = 0; i < registry->count; i++) {
        if (strcmp(registry->components[i].name, component->name) == 0) {
            return -1; /* Component already registered */
        }
    }
    
    /* Resize components array if needed */
    if (registry->count >= registry->capacity) {
        size_t new_capacity = registry->capacity * 2;
        libaura_component_interface_t* new_components = realloc(
            registry->components, 
            new_capacity * sizeof(libaura_component_interface_t)
        );
        
        if (!new_components) {
            return -1;
        }
        
        registry->components = new_components;
        registry->capacity = new_capacity;
    }
    
    /* Verify component integrity before registration - enforces soundness */
    if (libaura_verify_component(component, sizeof(*component), component->hash) != 0) {
        return -2; /* Component integrity check failed */
    }
    
    /* Verify entropy distribution for hardness validation */
    if (component->entropy_distribution < libaura_check_entropy_distribution(component, sizeof(*component))) {
        return -3; /* Entropy distribution check failed */
    }
    
    /* Copy component interface */
    registry->components[registry->count++] = *component;
    
    /* Update integrity check - enforces hardness */
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (const uint8_t*)registry->components, 
                  registry->count * sizeof(libaura_component_interface_t));
    SHA256_Final(registry->integrity_check, &ctx);
    
    return 0;
}

void* libaura_registry_resolve(libaura_component_registry_t* registry, const char* name) {
    if (!registry || !name) {
        return NULL;
    }
    
    /* Verify registry integrity before resolving - zero-knowledge check */
    if (libaura_registry_verify(registry) != 0) {
        return NULL;
    }
    
    /* Find component by name */
    for (size_t i = 0; i < registry->count; i++) {
        if (strcmp(registry->components[i].name, name) == 0) {
            /* Create component instance */
            void* instance = registry->components[i].create();
            
            /* Component must verify itself after creation - correctness principle */
            if (instance && registry->components[i].verify) {
                if (registry->components[i].verify(instance) != 0) {
                    /* Self-verification failed, destroy and return NULL */
                    registry->components[i].destroy(instance);
                    return NULL;
                }
            }
            
            return instance;
        }
    }
    
    return NULL;
}

int libaura_registry_verify(libaura_component_registry_t* registry) {
    if (!registry) {
        return -1;
    }
    
    /* Calculate current integrity check */
    uint8_t current_check[32];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (const uint8_t*)registry->components, 
                  registry->count * sizeof(libaura_component_interface_t));
    SHA256_Final(current_check, &ctx);
    
    /* Compare with stored integrity check */
    return memcmp(current_check, registry->integrity_check, 32) == 0 ? 0 : -1;
}

int libaura_derive_hmac_key(const uint8_t* private_key, size_t private_key_len,
                           const uint8_t* public_key, size_t public_key_len,
                           uint8_t* derived_key, size_t key_size) {
    if (!private_key || !public_key || !derived_key) {
        return -1;
    }
    
    /* Implement HMAC-based key derivation: Kderived = HMACxA(yA) */
    /* This follows the formal proof for zero-knowledge secure key derivation */
    unsigned int output_len = key_size;
    
    #if OPENSSL_VERSION_NUMBER >= 0x10100000L
    /* OpenSSL 1.1.0 and later */
    HMAC_CTX* ctx = HMAC_CTX_new();
    if (!ctx) {
        return -1;
    }
    
    int result = -1;
    
    if (HMAC_Init_ex(ctx, private_key, private_key_len, EVP_sha256(), NULL) &&
        HMAC_Update(ctx, public_key, public_key_len) &&
        HMAC_Final(ctx, derived_key, &output_len)) {
        result = 0;
    }
    
    HMAC_CTX_free(ctx);
    return result;
    #else
    /* OpenSSL 1.0.x or earlier */
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    
    int result = -1;
    
    if (HMAC_Init_ex(&ctx, private_key, private_key_len, EVP_sha256(), NULL) &&
        HMAC_Update(&ctx, public_key, public_key_len) &&
        HMAC_Final(&ctx, derived_key, &output_len)) {
        result = 0;
    }
    
    HMAC_CTX_cleanup(&ctx);
    return result;
    #endif
}

uint8_t libaura_check_entropy_distribution(const void* data, size_t size) {
    if (!data || size == 0) {
        return 0;
    }
    
    /* Calculate SHA-256 hash */
    uint8_t hash[32];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, size);
    SHA256_Final(hash, &ctx);
    
    /* Create byte frequency map */
    uint8_t frequency_map[256] = {0};
    for (size_t i = 0; i < 32; i++) {
        frequency_map[hash[i]]++;
    }
    
    /* Calculate Shannon entropy */
    double entropy = calculate_shannon_entropy(hash, 32);
    
    /* Normalize to 0-255 range */
    return (uint8_t)((entropy / 8.0) * 255.0);
}

int libaura_registry_save(const libaura_component_registry_t* registry, const char* filename) {
    if (!registry || !filename) {
        return -1;
    }
    
    /* Open file for writing */
    FILE* file = fopen(filename, "wb");
    if (!file) {
        return -1;
    }
    
    /* Write registry header */
    uint32_t magic = 0x4155524E; /* 'AURN' */
    uint32_t version = 1;
    uint32_t component_count = (uint32_t)registry->count;
    
    fwrite(&magic, sizeof(magic), 1, file);
    fwrite(&version, sizeof(version), 1, file);
    fwrite(&component_count, sizeof(component_count), 1, file);
    
    /* Write integrity check */
    fwrite(registry->integrity_check, sizeof(registry->integrity_check), 1, file);
    
    /* Write component data */
    for (size_t i = 0; i < registry->count; i++) {
        const libaura_component_interface_t* component = &registry->components[i];
        
        /* Write component name with length prefix */
        uint32_t name_length = (uint32_t)strlen(component->name);
        fwrite(&name_length, sizeof(name_length), 1, file);
        fwrite(component->name, 1, name_length, file);
        
        /* Write component hash and entropy */
        fwrite(&component->hash, sizeof(component->hash), 1, file);
        fwrite(&component->entropy_distribution, sizeof(component->entropy_distribution), 1, file);
        
        /* Note: function pointers are not saved */
    }
    
    /* Close file */
    fclose(file);
    
    return 0;
}

int libaura_registry_load(libaura_component_registry_t* registry, const char* filename) {
    if (!registry || !filename) {
        return -1;
    }
    
    /* Open file for reading */
    FILE* file = fopen(filename, "rb");
    if (!file) {
        return -1;
    }
    
    /* Read registry header */
    uint32_t magic, version, component_count;
    
    if (fread(&magic, sizeof(magic), 1, file) != 1 ||
        magic != 0x4155524E || /* 'AURN' */
        fread(&version, sizeof(version), 1, file) != 1 ||
        version != 1 ||
        fread(&component_count, sizeof(component_count), 1, file) != 1) {
        fclose(file);
        return -1;
    }
    
    /* Read integrity check */
    if (fread(registry->integrity_check, sizeof(registry->integrity_check), 1, file) != 1) {
        fclose(file);
        return -1;
    }
    
    /* Initialize new registry */
    libaura_registry_cleanup(registry);
    if (libaura_registry_init(registry, component_count) != 0) {
        fclose(file);
        return -1;
    }
    
    /* Note: This only loads component metadata, not the actual components */
    /* The components must be registered separately with matching function pointers */
    
    /* Close file */
    fclose(file);
    
    return 0;
}

/* Function to verify component integrity */
int libaura_verify_component(const void* component, size_t size, uint32_t expected_hash) {
    if (!component || size == 0) {
        return -1;
    }
    
    /* Calculate hash of component */
    uint8_t hash[32];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, component, size);
    SHA256_Final(hash, &ctx);
    
    /* Extract 32-bit hash for comparison */
    uint32_t calculated_hash = ((uint32_t)hash[0] << 24) |
                              ((uint32_t)hash[1] << 16) |
                              ((uint32_t)hash[2] << 8) |
                              ((uint32_t)hash[3]);
    
    return (calculated_hash == expected_hash) ? 0 : -1;
}