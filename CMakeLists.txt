# Copyright (c) 2021, Ericsson Software Technology
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without any warranty.

cmake_minimum_required(VERSION 3.12)
project(bpfjit LANGUAGES C)

# Add find package functions
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/")

find_package(Sljit REQUIRED)

add_library(bpfjit STATIC
  src/net/bpfjit.c
)

target_link_libraries(bpfjit
  PUBLIC
    sljit::sljit
)

target_include_directories(bpfjit
  PUBLIC
    $<INSTALL_INTERFACE:src>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# ----------------------------
# Installation configs

SET(CMAKE_CONF_INSTALL_DIR share/bpfjit)

install(FILES src/net/bpf.h src/net/bpfjit.h
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/net)

install(
  TARGETS bpfjit
  DESTINATION ${CMAKE_INSTALL_LIBDIR}
  EXPORT bpfjit-targets)

install(
  EXPORT bpfjit-targets
  FILE bpfjit-targets.cmake
  DESTINATION ${CMAKE_CONF_INSTALL_DIR}
)

# Generate config file that includes the exports
include(CMakePackageConfigHelpers)
configure_package_config_file(bpfjit-config.cmake.in
  "${CMAKE_CURRENT_BINARY_DIR}/bpfjit-config.cmake"
  INSTALL_DESTINATION ${CMAKE_CONF_INSTALL_DIR}
  NO_SET_AND_CHECK_MACRO
  NO_CHECK_REQUIRED_COMPONENTS_MACRO
)

install(
  FILES "${CMAKE_CURRENT_BINARY_DIR}/bpfjit-config.cmake"
  DESTINATION ${CMAKE_CONF_INSTALL_DIR}
)

# Export targets directly from the build tree
export(EXPORT bpfjit-targets
    FILE "${CMAKE_CURRENT_BINARY_DIR}/cmake/bpfjit-targets.cmake"
    NAMESPACE bpfjit::)

# ----------------------------
# Test suite

add_executable(bpfjit-test EXCLUDE_FROM_ALL
  test/main.c
)

target_link_libraries(bpfjit-test
  bpfjit
)
