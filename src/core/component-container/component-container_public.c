/**
 * @file component-container_public.c
 * @brief Implementation of the public component container interface
 * 
 * Implements the Phantom Encoder pattern for zero-knowledge component management
 * with proper isolation of public and private keys.
 * 
 * Copyright © 2025 OBINexus Computing - Computing from the Heart
 */

#include "libaura/core/component-container/component-container_public.h"
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

/* Constants */
#define LIBAURA_CHALLENGE_SALT_SIZE 16
#define LIBAURA_DESCRIPTOR_MAGIC 0x41555241 /* "AURA" */
#define LIBAURA_KEY_MAGIC 0x4B455941       /* "KEYA" */

/* Structure for the container context */
struct libaura_container_context {
    libaura_component_registry_t registry;
    uint8_t container_id[32];
    time_t creation_time;
    uint32_t challenge_counter;
};

/* Internal functions */
static int write_buffer_to_file(const char* file_path, const void* buffer, size_t size);
static int read_buffer_from_file(const char* file_path, void* buffer, size_t size);

libaura_container_context_t* libaura_container_create(size_t initial_capacity) {
    /* Allocate context */
    libaura_container_context_t* context = malloc(sizeof(libaura_container_context_t));
    if (!context) {
        return NULL;
    }
    
    /* Initialize registry */
    if (libaura_registry_init(&context->registry, initial_capacity) != 0) {
        free(context);
        return NULL;
    }
    
    /* Generate unique container ID */
    if (RAND_bytes(context->container_id, sizeof(context->container_id)) != 1) {
        libaura_registry_cleanup(&context->registry);
        free(context);
        return NULL;
    }
    
    /* Set creation time */
    context->creation_time = time(NULL);
    context->challenge_counter = 0;
    
    return context;
}

void libaura_container_destroy(libaura_container_context_t* context) {
    if (!context) {
        return;
    }
    
    /* Clean up registry */
    libaura_registry_cleanup(&context->registry);
    
    /* Clear sensitive data */
    memset(context->container_id, 0, sizeof(context->container_id));
    
    /* Free context */
    free(context);
}

int libaura_container_register_component(libaura_container_context_t* context, 
                                        const libaura_component_interface_t* component) {
    if (!context || !component) {
        return -1;
    }
    
    /* Register component with registry */
    return libaura_registry_register(&context->registry, component);
}

void* libaura_container_resolve(libaura_container_context_t* context, const char* name) {
    if (!context || !name) {
        return NULL;
    }
    
    /* Resolve component from registry */
    return libaura_registry_resolve(&context->registry, name);
}

const libaura_component_registry_t* libaura_container_get_registry(const libaura_container_context_t* context) {
    if (!context) {
        return NULL;
    }
    
    return &context->registry;
}

int libaura_container_create_challenge(const libaura_container_context_t* context,
                                     const char* component_name,
                                     uint8_t* challenge,
                                     size_t challenge_size) {
    if (!context || !component_name || !challenge || challenge_size < 32) {
        return -1;
    }
    
    /* Generate random challenge */
    if (RAND_bytes(challenge, challenge_size) != 1) {
        return -1;
    }
    
    /* Mix in container ID and component name for context binding */
    uint8_t name_hash[32];
    SHA256_CTX sha_ctx;
    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, component_name, strlen(component_name));
    SHA256_Final(name_hash, &sha_ctx);
    
    /* XOR the first 32 bytes with container ID and name hash */
    for (size_t i = 0; i < 32 && i < challenge_size; i++) {
        challenge[i] ^= context->container_id[i] ^ name_hash[i];
    }
    
    return 0;
}

int libaura_container_verify_response(const libaura_container_context_t* context,
                                    const char* component_name,
                                    const uint8_t* challenge,
                                    size_t challenge_size,
                                    const uint8_t* response,
                                    size_t response_size) {
    if (!context || !component_name || !challenge || !response ||
        challenge_size < 32 || response_size < 64) {
        return -1;
    }
    
    /* Find component in registry */
    bool found = false;
    libaura_component_interface_t component;
    
    for (size_t i = 0; i < context->registry.count; i++) {
        if (strcmp(context->registry.components[i].name, component_name) == 0) {
            component = context->registry.components[i];
            found = true;
            break;
        }
    }
    
    if (!found) {
        return -1;
    }
    
    /* Verify response using hash-based verification */
    uint8_t expected_response[64];
    uint8_t combined[96]; /* 32 bytes for challenge + 32 bytes for component hash + 32 bytes for context */
    
    /* Combine challenge with component hash and context */
    memcpy(combined, challenge, 32);
    memcpy(combined + 32, &component.hash, sizeof(component.hash));
    memcpy(combined + 36, context->container_id, 32);
    
    /* Generate HMAC */
    unsigned int md_len = 64;
    HMAC(EVP_sha512(), combined, sizeof(combined), 
         challenge, challenge_size, expected_response, &md_len);
    
    /* Compare with provided response */
    return memcmp(expected_response, response, 64) == 0 ? 0 : -1;
}

int libaura_container_create_descriptor(const char* component_name,
                                      const char* version,
                                      uint32_t features,
                                      const char* output_file) {
    if (!component_name || !version || !output_file) {
        return -1;
    }
    
    /* Create descriptor file format */
    struct {
        uint32_t magic;
        uint32_t version_number;
        uint32_t features;
        uint32_t name_length;
        uint32_t version_length;
        uint8_t id[32];
        uint8_t reserved[32];
    } descriptor;
    
    /* Set descriptor values */
    descriptor.magic = LIBAURA_DESCRIPTOR_MAGIC;
    descriptor.version_number = 1;
    descriptor.features = features;
    descriptor.name_length = strlen(component_name);
    descriptor.version_length = strlen(version);
    
    /* Generate ID based on component name and version */
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, component_name, strlen(component_name));
    SHA256_Update(&ctx, version, strlen(version));
    SHA256_Final(descriptor.id, &ctx);
    
    /* Clear reserved area */
    memset(descriptor.reserved, 0, sizeof(descriptor.reserved));
    
    /* Write descriptor to file */
    FILE* file = fopen(output_file, "wb");
    if (!file) {
        return -1;
    }
    
    /* Write descriptor header */
    if (fwrite(&descriptor, sizeof(descriptor), 1, file) != 1) {
        fclose(file);
        return -1;
    }
    
    /* Write component name */
    if (fwrite(component_name, 1, descriptor.name_length, file) != descriptor.name_length) {
        fclose(file);
        return -1;
    }
    
    /* Write component version */
    if (fwrite(version, 1, descriptor.version_length, file) != descriptor.version_length) {
        fclose(file);
        return -1;
    }
    
    fclose(file);
    return 0;
}

int libaura_container_create_key(const char* component_name,
                               const char* version,
                               uint32_t features,
                               const char* output_file) {
    if (!component_name || !version || !output_file) {
        return -1;
    }
    
    /* Create key file format */
    struct {
        uint32_t magic;
        uint32_t version_number;
        uint32_t features;
        uint64_t timestamp;
        uint8_t key[64];
        uint8_t salt[16];
        uint8_t reserved[32];
    } key_file;
    
    /* Set key file values */
    key_file.magic = LIBAURA_KEY_MAGIC;
    key_file.version_number = 1;
    key_file.features = features;
    key_file.timestamp = (uint64_t)time(NULL);
    
    /* Generate random salt */
    if (RAND_bytes(key_file.salt, sizeof(key_file.salt)) != 1) {
        return -1;
    }
    
    /* Generate key from component name, version, and salt */
    SHA512_CTX ctx;
    SHA512_Init(&ctx);
    SHA512_Update(&ctx, component_name, strlen(component_name));
    SHA512_Update(&ctx, version, strlen(version));
    SHA512_Update(&ctx, key_file.salt, sizeof(key_file.salt));
    SHA512_Final(key_file.key, &ctx);
    
    /* Clear reserved area */
    memset(key_file.reserved, 0, sizeof(key_file.reserved));
    
    /* Write key file */
    FILE* file = fopen(output_file, "wb");
    if (!file) {
        return -1;
    }
    
    if (fwrite(&key_file, sizeof(key_file), 1, file) != 1) {
        fclose(file);
        return -1;
    }
    
    fclose(file);
    return 0;
}

int libaura_container_load_descriptor(const char* file_path,
                                    libaura_component_descriptor_t* descriptor) {
    if (!file_path || !descriptor) {
        return -1;
    }
    
    /* Open descriptor file */
    FILE* file = fopen(file_path, "rb");
    if (!file) {
        return -1;
    }
    
    /* Read descriptor header */
    struct {
        uint32_t magic;
        uint32_t version_number;
        uint32_t features;
        uint32_t name_length;
        uint32_t version_length;
        uint8_t id[32];
        uint8_t reserved[32];
    } file_descriptor;
    
    if (fread(&file_descriptor, sizeof(file_descriptor), 1, file) != 1 ||
        file_descriptor.magic != LIBAURA_DESCRIPTOR_MAGIC) {
        fclose(file);
        return -1;
    }
    
    /* Allocate memory for component name and version */
    char* name = malloc(file_descriptor.name_length + 1);
    char* version = malloc(file_descriptor.version_length + 1);
    
    if (!name || !version) {
        free(name);
        free(version);
        fclose(file);
        return -1;
    }
    
    /* Read component name */
    if (fread(name, 1, file_descriptor.name_length, file) != file_descriptor.name_length) {
        free(name);
        free(version);
        fclose(file);
        return -1;
    }
    name[file_descriptor.name_length] = '\0';
    
    /* Read component version */
    if (fread(version, 1, file_descriptor.version_length, file) != file_descriptor.version_length) {
        free(name);
        free(version);
        fclose(file);
        return -1;
    }
    version[file_descriptor.version_length] = '\0';
    
    /* Set descriptor values */
    descriptor->name = name;
    descriptor->version = version;
    descriptor->features = file_descriptor.features;
    memcpy(descriptor->id, file_descriptor.id, sizeof(descriptor->id));
    
    /* Key is not loaded from descriptor file */
    memset(descriptor->key, 0, sizeof(descriptor->key));
    
    fclose(file);
    return 0;
}

int libaura_container_load_key(const char* file_path,
                             libaura_component_descriptor_t* descriptor) {
    if (!file_path || !descriptor) {
        return -1;
    }
    
    /* Open key file */
    FILE* file = fopen(file_path, "rb");
    if (!file) {
        return -1;
    }
    
    /* Read key file header */
    struct {
        uint32_t magic;
        uint32_t version_number;
        uint32_t features;
        uint64_t timestamp;
        uint8_t key[64];
        uint8_t salt[16];
        uint8_t reserved[32];
    } key_file;
    
    if (fread(&key_file, sizeof(key_file), 1, file) != 1 ||
        key_file.magic != LIBAURA_KEY_MAGIC) {
        fclose(file);
        return -1;
    }
    
    /* Check if features match */
    if (key_file.features != descriptor->features) {
        fclose(file);
        return -1;
    }
    
    /* Copy key to descriptor */
    memcpy(descriptor->key, key_file.key, sizeof(descriptor->key));
    
    fclose(file);
    return 0;
}

int libaura_container_derive_id(const libaura_container_context_t* context,
                              const char* base_component,
                              const char* purpose,
                              uint8_t* derived_id,
                              size_t derived_id_size) {
    if (!context || !base_component || !purpose || !derived_id || derived_id_size < 32) {
        return -1;
    }
    
    /* Find base component */
    bool found = false;
    libaura_component_interface_t component;
    
    for (size_t i = 0; i < context->registry.count; i++) {
        if (strcmp(context->registry.components[i].name, base_component) == 0) {
            component = context->registry.components[i];
            found = true;
            break;
        }
    }
    
    if (!found) {
        return -1;
    }
    
    /* Create derivation context */
    uint8_t derivation_context[128];
    size_t context_size = 0;
    
    /* Add component hash */
    memcpy(derivation_context + context_size, &component.hash, sizeof(component.hash));
    context_size += sizeof(component.hash);
    
    /* Add purpose */
    size_t purpose_len = strlen(purpose);
    if (purpose_len > 64) {
        purpose_len = 64;
    }
    memcpy(derivation_context + context_size, purpose, purpose_len);
    context_size += purpose_len;
    
    /* Add container ID */
    memcpy(derivation_context + context_size, context->container_id, 32);
    context_size += 32;
    
    /* Derive ID using HMAC-SHA256 */
    HMAC(EVP_sha256(), derivation_context, context_size,
         (const unsigned char*)base_component, strlen(base_component),
         derived_id, (unsigned int*)&derived_id_size);
    
    return 0;
}

/* Internal utility functions */
static int write_buffer_to_file(const char* file_path, const void* buffer, size_t size) {
    if (!file_path || !buffer || size == 0) {
        return -1;
    }
    
    FILE* file = fopen(file_path, "wb");
    if (!file) {
        return -1;
    }
    
    size_t written = fwrite(buffer, 1, size, file);
    fclose(file);
    
    return (written == size) ? 0 : -1;
}

static int read_buffer_from_file(const char* file_path, void* buffer, size_t size) {
    if (!file_path || !buffer || size == 0) {
        return -1;
    }
    
    FILE* file = fopen(file_path, "rb");
    if (!file) {
        return -1;
    }
    
    size_t read_size = fread(buffer, 1, size, file);
    fclose(file);
    
    return (read_size == size) ? 0 : -1;
}