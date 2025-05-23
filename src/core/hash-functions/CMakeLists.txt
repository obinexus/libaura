# LibAura Hash Functions Module CMakeLists.txt

# Source files
set(HASH_FUNCTIONS_SOURCES
    hash-functions_public.c
    hash-functions_priv.c
    hash-functions_verify.c
    hash-functions_config.c
)

# Add library target
add_library(libaura-hash-functions STATIC
    ${HASH_FUNCTIONS_SOURCES}
)

# Set include directories
target_include_directories(libaura-hash-functions PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

# Set link libraries
target_link_libraries(libaura-hash-functions PUBLIC
    libaura-component-container
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Install headers
install(FILES
    ${CMAKE_SOURCE_DIR}/include/libaura/core/hash-functions/hash-functions_public.h
    ${CMAKE_SOURCE_DIR}/include/libaura/core/hash-functions/hash-functions_types.h
    ${CMAKE_SOURCE_DIR}/include/libaura/core/hash-functions/hash-functions_constants.h
    ${CMAKE_SOURCE_DIR}/include/libaura/core/hash-functions/hash-functions_config.h
    DESTINATION include/libaura/core/hash-functions
)

# Install library
install(TARGETS libaura-hash-functions
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

# Add tests if testing is enabled
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()