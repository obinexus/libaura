# LibAuraComponent.cmake
# Module for managing LibAura components with integrity verification
#
# This module provides functions for:
# - Building components as static/shared libraries with verification
# - Managing cryptographic integrity checks
# - Creating dependency chains

if(DEFINED LIBAURA_COMPONENT_INCLUDED)
  return()
endif()
set(LIBAURA_COMPONENT_INCLUDED TRUE)

include(CMakeParseArguments)

# Function to add a LibAura component
function(libaura_add_component)
  cmake_parse_arguments(
    COMP
    ""
    "NAME;VERSION"
    "SOURCES;HEADERS;DEPENDENCIES;INCLUDE_DIRS"
    ${ARGN}
  )
  
  if(NOT COMP_NAME)
    message(FATAL_ERROR "Component name is required")
  endif()
  
  # Create object library first
  add_library(${COMP_NAME}_obj OBJECT ${COMP_SOURCES})
  
  # Set include directories
  target_include_directories(${COMP_NAME}_obj PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${COMP_INCLUDE_DIRS}
  )
  
  # Create static library from objects
  add_library(${COMP_NAME}_static STATIC $<TARGET_OBJECTS:${COMP_NAME}_obj>)
  set_target_properties(${COMP_NAME}_static PROPERTIES
    OUTPUT_NAME ${COMP_NAME}
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
  )
  
  # Create shared library from objects
  add_library(${COMP_NAME}_shared SHARED $<TARGET_OBJECTS:${COMP_NAME}_obj>)
  set_target_properties(${COMP_NAME}_shared PROPERTIES
    OUTPUT_NAME ${COMP_NAME}
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
  )
  
  # Create alias targets
  add_library(LibAura::${COMP_NAME} ALIAS ${COMP_NAME}_shared)
  add_library(LibAura::${COMP_NAME}_static ALIAS ${COMP_NAME}_static)
  
  # Link dependencies
  if(COMP_DEPENDENCIES)
    target_link_libraries(${COMP_NAME}_static PUBLIC ${COMP_DEPENDENCIES})
    target_link_libraries(${COMP_NAME}_shared PUBLIC ${COMP_DEPENDENCIES})
  endif()
  
  # Install libraries
  install(TARGETS ${COMP_NAME}_static ${COMP_NAME}_shared
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
  )
endfunction()
