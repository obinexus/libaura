# Component Container CMakeLists.txt
# Core IoC container implementation with zero-knowledge verification

# Source files
set(COMPONENT_CONTAINER_SOURCES
    component-container_registry.c
    component-container_public.c
    component-container_priv.c
    component-container_config.c
    component-container_verify.c
)

# Header files
set(COMPONENT_CONTAINER_HEADERS
    ${CMAKE_SOURCE_DIR}/include/libaura/core/component-container/component-container_registry.h
    ${CMAKE_SOURCE_DIR}/include/libaura/core/component-container/component-container_public.h
    ${CMAKE_SOURCE_DIR}/include/libaura/core/component-container/component-container_config.h
    ${CMAKE_SOURCE_DIR}/include/libaura/core/component-container/component-container_verify.h
    component-container_priv.h
)

# Create static library
add_library(component-container STATIC
    ${COMPONENT_CONTAINER_SOURCES}
    ${COMPONENT_CONTAINER_HEADERS}
)

# Set include directories
target_include_directories(component-container PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

# Find and link OpenSSL
find_package(OpenSSL REQUIRED)
target_link_libraries(component-container PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Set output properties
set_target_properties(component-container PROPERTIES
    OUTPUT_NAME "aura-component-container"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
)

# Install targets
install(TARGETS component-container
    ARCHIVE DESTINATION lib
)

# Install headers
install(FILES
    ${CMAKE_SOURCE_DIR}/include/libaura/core/component-container/component-container_registry.h
    ${CMAKE_SOURCE_DIR}/include/libaura/core/component-container/component-container_public.h
    ${CMAKE_SOURCE_DIR}/include/libaura/core/component-container/component-container_config.h
    ${CMAKE_SOURCE_DIR}/include/libaura/core/component-container/component-container_verify.h
    DESTINATION include/libaura/core/component-container
)

# Create object library for in-project usage
add_library(component-container-obj OBJECT
    ${COMPONENT_CONTAINER_SOURCES}
    ${COMPONENT_CONTAINER_HEADERS}
)

# Set include directories for object library
target_include_directories(component-container-obj PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

# Link object library with OpenSSL
target_link_libraries(component-container-obj PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Export the object library target
set_target_properties(component-container-obj PROPERTIES
    POSITION_INDEPENDENT_CODE ON
)

# Add compiler options for security
target_compile_options(component-container PRIVATE
    -Wall
    -Wextra
    -Werror
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
)

# Add compiler definitions
target_compile_definitions(component-container PRIVATE
    LIBAURA_COMPONENT_CONTAINER_EXPORTS
)

# Add tests if testing is enabled
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()