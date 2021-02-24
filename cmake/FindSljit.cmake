# Copyright (c) 2021, Ericsson Software Technology
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without any warranty.

# Try to find the sljit library
# Once done this will define
#  SLJIT_FOUND - System has sljit
#  SLJIT_INCLUDE_DIR - The sljit include directory
#  SLJIT_LIBRARY - The sljit library

include(GNUInstallDirs)

find_library(SLJIT_LIBRARY
  NAMES sljit
  HINTS
    ${CMAKE_PREFIX_PATH}
  PATH_SUFFIXES
    ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}
)

find_path(SLJIT_INCLUDE_DIR
  NAMES sljitLir.h
  HINTS
    ${CMAKE_PREFIX_PATH}
  PATH_SUFFIXES
    ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR}
)

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(Sljit DEFAULT_MSG
                                  SLJIT_LIBRARY
                                  SLJIT_INCLUDE_DIR)

mark_as_advanced(SLJIT_LIBRARY SLJIT_INCLUDE_DIR)

if(SLJIT_FOUND AND NOT TARGET sljit::sljit)
  add_library(sljit::sljit SHARED IMPORTED)
  set_target_properties(
    sljit::sljit
    PROPERTIES
      INTERFACE_INCLUDE_DIRECTORIES "${SLJIT_INCLUDE_DIR}"
      IMPORTED_LOCATION ${SLJIT_LIBRARY})
endif()
