# Include LibAura component module
include(LibAuraComponent)

# Add core components
add_subdirectory(core)

# Add CLI components
add_subdirectory(cli)

# Create libaura core library
add_library(libaura_core SHARED)

# Set properties
set_target_properties(libaura_core PROPERTIES
  OUTPUT_NAME aura
  LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
)

# Link component libraries
target_link_libraries(libaura_core PUBLIC
  component-container_static
  crypto-auth_static
  checksum-verification_static
  hash-functions_static
  OpenSSL::SSL
  OpenSSL::Crypto
)

# Install library
install(TARGETS libaura_core
  ARCHIVE DESTINATION lib
  LIBRARY DESTINATION lib
)
