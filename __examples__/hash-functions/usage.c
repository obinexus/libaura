/* Example: Using the hash configuration system */

#include "libaura/core/hash-functions/hash-functions_public.h"
#include "libaura/core/hash-functions/hash-functions_config.h"

int main() {
    /* Initialize hash module (loads default configuration) */
    libaura_hash_initialize();
    
    /* Create a different configuration for a specific use case */
    libaura_hash_config_t custom_config;
    libaura_hash_config_init(&custom_config);
    
    /* Customize configuration for production */
    custom_config.environment = LIBAURA_ENV_PRODUCTION;
    custom_config.default_algorithm = LIBAURA_HASH_AURA512;
    custom_config.min_entropy_aura512 = 240; /* Higher threshold */
    
    /* Initialize hash context */
    libaura_hash_context_t context;
    libaura_hash_init(&context, LIBAURA_DIGEST_512);
    
    /* Apply custom configuration to context */
    libaura_hash_config_apply(&custom_config, &context);
    
    /* Use the configured hash context */
    const char* data = "Test data";
    uint8_t digest[64];
    
    libaura_hash_update(&context, data, strlen(data));
    libaura_hash_final(&context, digest);
    
    /* Save custom configuration for future use */
    libaura_hash_config_save(&custom_config, "custom_hash.config");
    
    /* Clean up */
    libaura_hash_config_cleanup(&custom_config);
    libaura_hash_cleanup();
    
    return 0;
}