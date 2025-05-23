# LibAura Checksum Verification Tests CMakeLists.txt

# Add test executable for hash bridge
add_executable(test_hash_bridge
    test_hash_bridge.c
)

# Link with required libraries
target_link_libraries(test_hash_bridge
    libaura-checksum-verification
    libaura-hash-functions
    libaura-component-container
)

# Add test to CTest
add_test(
    NAME TestHashBridge
    COMMAND test_hash_bridge
)

# Set environment variables for test if needed
set_tests_properties(TestHashBridge PROPERTIES
    ENVIRONMENT "LIBAURA_TEST_MODE=1"
)