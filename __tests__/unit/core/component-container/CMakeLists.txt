# Component Container Unit Tests CMakeLists.txt

# Source files for registry tests
set(TEST_REGISTRY_SOURCES
    test_registry.c
)

# Source files for verification tests
set(TEST_VERIFY_SOURCES
    test_verify.c
)

# Create registry test executable
add_executable(test_component_registry
    ${TEST_REGISTRY_SOURCES}
)

# Create verification test executable
add_executable(test_component_verify
    ${TEST_VERIFY_SOURCES}
)

# Set include directories
target_include_directories(test_component_registry PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

target_include_directories(test_component_verify PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

# Link with component container library
target_link_libraries(test_component_registry PRIVATE
    component-container
    OpenSSL::SSL
    OpenSSL::Crypto
)

target_link_libraries(test_component_verify PRIVATE
    component-container
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Add tests to CTest
add_test(
    NAME test_component_registry
    COMMAND test_component_registry
)

add_test(
    NAME test_component_verify
    COMMAND test_component_verify
)

# Set test properties
set_tests_properties(test_component_registry PROPERTIES
    PASS_REGULAR_EXPRESSION "All tests passed successfully!"
)

set_tests_properties(test_component_verify PROPERTIES
    PASS_REGULAR_EXPRESSION "All verification tests passed successfully!"
)

# Copy test data files if needed
# file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/test_data DESTINATION ${CMAKE_CURRENT_BINARY_DIR})