cmake_minimum_required(VERSION 2.8)
project(mcu)


#-----------------------------------------------------------------------------
# Create version header file

find_package(Git)
if(GIT_FOUND)
  execute_process(COMMAND git "describe" "--tags" OUTPUT_VARIABLE GIT_COMMIT_HASH WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} OUTPUT_STRIP_TRAILING_WHITESPACE)
else()
  set(GIT_COMMIT_HASH "Git not found.")
endif()
set(VERSION_STRING "${GIT_COMMIT_HASH}")

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/src/version.h.in
               ${CMAKE_CURRENT_SOURCE_DIR}/src/version.h)
set(version_file "${CMAKE_CURRENT_SOURCE_DIR}/src/version.h")


#-----------------------------------------------------------------------------
# Options for building

option(BUILD_TESTS "Build the unit tests." ON)
option(BUILD_COVERAGE "Compile with test coverage flags." OFF)
option(BUILD_DOCUMENTATION "Build the Doxygen documentation." ON)
option(CMAKE_VERBOSE_MAKEFILE "Verbose build." OFF)
option(USE_UECC_LIB "Use micro ECC instead bitcoin's secp256k1 library." OFF)


#-----------------------------------------------------------------------------
# Print system information and build options

message(STATUS "General -------------------------------------")
message(STATUS "mcu version:            ${VERSION_STRING}")
message(STATUS "Git Commit Hash:        ${GIT_COMMIT_HASH}")
message(STATUS "CMake version:          ${CMAKE_VERSION}")
message(STATUS "System:                 ${CMAKE_SYSTEM}")
message(STATUS "Processor:              ${CMAKE_SYSTEM_PROCESSOR}")

if(USE_UECC_LIB)
    message(STATUS "ECC library:            micro ECC")
else()
    message(STATUS "ECC library:            secp256k1")
endif()

message(STATUS "Verbose:                ${CMAKE_VERBOSE_MAKEFILE}")
message(STATUS "Testing:                ${BUILD_TESTS}")
message(STATUS "Coverage:               ${BUILD_COVERAGE}")
message(STATUS "Documentation:          ${BUILD_DOCUMENTATION}")


#-----------------------------------------------------------------------------
# Collect all binaries into bin subdirectory

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_CURRENT_BINARY_DIR}/bin)
set(LIBRARY_OUTPUT_PATH  ${CMAKE_CURRENT_BINARY_DIR}/lib)


#-----------------------------------------------------------------------------
# Compiler flags

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99")
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -g") # valgrind
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Os")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -W -Wall -Wextra -Werror -pedantic -Wredundant-decls -Wstrict-prototypes -Wundef -Wshadow -Wpointer-arith -Wmultichar -Wformat-nonliteral -Winit-self -Wformat-security -Wold-style-definition -Wmissing-include-dirs -Wbad-function-cast -Winline -Wnested-externs -Wfloat-equal -Wmissing-declarations -Wswitch-default -Wwrite-strings -Wcast-qual -Wmissing-prototypes")

if(APPLE)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-deprecated-declarations")
  set(CMAKE_C_LINK_FLAGS "${CMAKE_C_LINK_FLAGS} -framework AppKit -framework IOKit")
  set(CMAKE_MACOSX_RPATH ON)
endif()

if(CMAKE_COMPILER_IS_GNUCC)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-function")
endif()

message(STATUS "C Compiler ID: ${CMAKE_C_COMPILER_ID}")
message(STATUS "C Flags:       ${CMAKE_C_FLAGS}")
message(STATUS "C link flags:  ${CMAKE_C_LINK_FLAGS}")


#-----------------------------------------------------------------------------
# Test coverage flags

if(BUILD_COVERAGE)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage")
  set(CMAKE_C_LINK_FLAGS "${CMAKE_C_LINK_FLAGS} -fprofile-arcs")
endif()


#-----------------------------------------------------------------------------
# Get submodules

execute_process(COMMAND git "submodule" "update" "--init" "--recursive" WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})


#-----------------------------------------------------------------------------
# Third party libraries

if(BUILD_TESTS)
  find_package(OpenSSL REQUIRED)
    if(NOT WIN32)
      if(NOT CONTINUOUS_INTEGRATION)
        find_library(HIDAPI_LIBRARY
          NAMES hidapi hidapi-libusb)

        find_path(HIDAPI_INCLUDE_DIR
          NAMES hidapi.h
          PATH_SUFFIXES
          hidapi)

        if(!HIDAPI_FOUND)
          message(FATAL_ERROR "hidapi not found.")
        endif()
      endif()
    endif()
endif()


#-----------------------------------------------------------------------------
# Force out-of-source build

if(${CMAKE_CURRENT_SOURCE_DIR} STREQUAL ${CMAKE_CURRENT_BINARY_DIR})
message(FATAL_ERROR "CMake generation is not allowed within the source directory!
Remove the CMakeCache.txt file and try again from another folder, e.g.:

   rm CMakeCache.txt
   mkdir build
   cd build
   cmake ..
")
endif()


#-----------------------------------------------------------------------------
# Default to Release build

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING
      "Choose the type of build, options are: None Debug Release RelWithDebInfo MinSizeRel."
      FORCE)
endif()


#-----------------------------------------------------------------------------
# Build Documentation

if(BUILD_DOCUMENTATION)
  set(DOC_GRAPHS "YES" CACHE STRING "Create dependency graphs (needs graphviz)")
  set(DOC_FULLGRAPHS "NO" CACHE STRING "Create call/callee graphs (large)")

  find_program(DOT_PATH dot)

  if (DOT_PATH STREQUAL "DOT_PATH-NOTFOUND")
    message("Doxygen: graphviz not found - graphs disabled")
    set(DOC_GRAPHS "NO")
  endif()

  find_package(Doxygen)
  if(DOXYGEN_FOUND)
    configure_file("doc/Doxyfile.in" "Doxyfile" @ONLY)
    add_custom_target(doc
      ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
      WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
      COMMENT "Generating API documentation with Doxygen.." VERBATIM)
  endif()
endif()


#-----------------------------------------------------------------------------
# Source Definitions

if(CONTINUOUS_INTEGRATION)
  add_definitions(-DCONTINUOUS_INTEGRATION)
endif()

if(BUILD_TESTS)
  add_definitions(-DTESTING)
endif()

if(USE_UECC_LIB)
    add_definitions(-DECC_USE_UECC_LIB)
endif()


#-----------------------------------------------------------------------------
# Build source

add_subdirectory(src)

if(BUILD_TESTS)
  add_subdirectory(tests)
  add_test(NAME tests_unit COMMAND tests_unit)
  add_test(NAME tests_openssl COMMAND tests_openssl 200)
  add_test(NAME tests_cmdline COMMAND tests_cmdline '{"name":""}')
  add_test(NAME tests_api COMMAND tests_api)
  add_test(NAME tests_secp256k1 COMMAND tests_secp256k1 2)
  enable_testing()
endif()
