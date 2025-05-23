cmake_minimum_required(VERSION 3.13)

# LibAura Project
project(LibAura VERSION 1.0.0 LANGUAGES C)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Build options
option(BUILD_SHARED_LIBS "Build shared libraries" ON)
option(BUILD_TESTING "Build tests" ON)
option(ENABLE_COVERAGE "Enable code coverage" OFF)
option(ENABLE_CRYPTO "Enable cryptographic functionality" ON)

# Include CMake modules
list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/modules)

# Find required packages
find_package(OpenSSL REQUIRED)

# Include directories
include_directories(include)

# Add subdirectories
add_subdirectory(src)

if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests)
endif()

# Install configuration
install(DIRECTORY include/libaura DESTINATION include)
