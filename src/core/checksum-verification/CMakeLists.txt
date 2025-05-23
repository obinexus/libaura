# LibAura Checksum Verification Module CMakeLists.txt

# Source files
set(CHECKSUM_VERIFICATION_SOURCES
    checksum-verification_priv.c
    checksum-verification_public.c
    checksum-verification_verify.c
    checksum-verification_hash_bridge.c
)

# Add library target
add_library(libaura-checksum-verification STATIC
    ${CHECKSUM_VERIFICATION_SOURCES}
)

# Set include directories
target_include_directories(libaura-checksum-verification PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)

# Set link libraries
target_link_libraries(libaura-checksum-verification PUBLIC
    libaura-component-container
    libaura-hash-functions
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Install headers
install(FILES
    ${CMAKE_SOURCE_DIR}/include/libaura/core/checksum-verification/checksum-verification_public.h
    ${CMAKE_SOURCE_DIR}/include/libaura/core/checksum-verification/checksum-verification_hash_bridge.h
    DESTINATION include/libaura/core/checksum-verification
)

# Install library
install(TARGETS libaura-checksum-verification
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

# Add tests if testing is enabled
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()