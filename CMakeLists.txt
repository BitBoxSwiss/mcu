#-----------------------------------------------------------------------------
# CmakeLists.txt for the Digital Bitbox 
# Copyright (c) 2015-2016 Lucas Betschart, Douglas J. Bakkum
# MIT License


cmake_minimum_required(VERSION 2.8.5)

if(BUILD_TYPE STREQUAL "firmware")
elseif(BUILD_TYPE STREQUAL "bootloader")
elseif(BUILD_TYPE STREQUAL "test")
else()
    message(FATAL_ERROR "Invalid build type: ${BUILD_TYPE}. Build with:
    cmake .. -DBUILD_TYPE=type   # 'type' can be 'test', 'firmware', or 'bootloader'
    ")
endif()

    
set(MYPROJECT ${BUILD_TYPE})
project(${MYPROJECT} C)

#-----------------------------------------------------------------------------
# Options for building

if(BUILD_TYPE STREQUAL "bootloader")
option(USE_UECC_LIB "Use micro ECC instead bitcoin's secp256k1 library." ON)
else()
option(USE_UECC_LIB "Use micro ECC instead bitcoin's secp256k1 library." OFF)
endif()
option(BUILD_COVERAGE "Compile with test coverage flags." OFF)
option(BUILD_VALGRIND "Compile with debug symbols." OFF)
option(BUILD_DOCUMENTATION "Build the Doxygen documentation." OFF)
option(CMAKE_VERBOSE_MAKEFILE "Verbose build." OFF)


if(NOT BUILD_TYPE STREQUAL "test")
    set(ELF ${MYPROJECT}.elf)
    set(CMAKE_TOOLCHAIN_FILE arm.cmake)
    include(${CMAKE_TOOLCHAIN_FILE})
endif()

if(CONTINUOUS_INTEGRATION AND BUILD_TYPE STREQUAL "test")
    set(BUILD_COVERAGE "ON")
    set(BUILD_VALGRIND "ON")
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
# Create version header file

find_package(Git)
if(GIT_FOUND)
    execute_process(COMMAND git "describe" "--tags" OUTPUT_VARIABLE GIT_COMMIT_HASH WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process(COMMAND git "describe" "--tags" "--abbrev=0" OUTPUT_VARIABLE GIT_COMMIT_HASH_SHORT WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} OUTPUT_STRIP_TRAILING_WHITESPACE)
    string(REPLACE "." ";" VERSION_LIST ${GIT_COMMIT_HASH_SHORT})
    list(GET VERSION_LIST 0 vMAJOR)
    list(GET VERSION_LIST 1 MINOR)
    list(GET VERSION_LIST 2 PATCH)
    string(REPLACE "v" "" MAJOR ${vMAJOR})
else()
    set(GIT_COMMIT_HASH "Git not found.")
endif()
set(VERSION_STRING "${GIT_COMMIT_HASH}")
set(VERSION_STRING_SHORT "${GIT_COMMIT_HASH_SHORT}")
set(VERSION_STRING_MAJOR ${MAJOR})
set(VERSION_STRING_MINOR ${MINOR})
set(VERSION_STRING_PATCH ${PATCH})

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/src/version.h.in
               ${CMAKE_CURRENT_SOURCE_DIR}/src/version.h)


#-----------------------------------------------------------------------------
# Source Definitions

if(CONTINUOUS_INTEGRATION)
  add_definitions(-DCONTINUOUS_INTEGRATION)
endif()

if(BUILD_TYPE STREQUAL "test")
  add_definitions(-DTESTING)
endif()

if(BUILD_TYPE STREQUAL "bootloader")
    add_definitions(-DBOOTLOADER)
endif()

add_definitions(-DuECC_OPTIMIZATION_LEVEL=4) # match to compiler optimization level
    
if(USE_SECP256K1_LIB)
    add_definitions(-DECC_USE_SECP256K1_LIB)
    add_definitions(-DSECP256K1_BUILD=1)
endif()


#-----------------------------------------------------------------------------
# Print system information and build options

message(STATUS "\n\n=============================================")
message(STATUS "            - General -")
message(STATUS "MCU version:            ${VERSION_STRING}")
message(STATUS "CMake version:          ${CMAKE_VERSION}")
message(STATUS "System:                 ${CMAKE_SYSTEM}")
message(STATUS "Processor:              ${CMAKE_SYSTEM_PROCESSOR}")
message(STATUS "             - Build -")
message(STATUS "Compiler:               ${CMAKE_C_COMPILER}")
message(STATUS "Linker:                 ${CMAKE_LINKER}")
message(STATUS "Archiver:               ${CMAKE_AR}")
message(STATUS "            - Options -")
message(STATUS "Build type:             ${BUILD_TYPE}")
message(STATUS "Verbose:                ${CMAKE_VERBOSE_MAKEFILE}")
message(STATUS "Documentation:          ${BUILD_DOCUMENTATION}  (make doc)")
message(STATUS "Coverage flags:         ${BUILD_COVERAGE}")
message(STATUS "Debug symbols:          ${BUILD_VALGRIND}")
if(USE_SECP256K1_LIB)
    message(STATUS "ECC library:            micro ECC & libsecp256k1 for bitcoin")
else()
    message(STATUS "ECC library:            only micro ECC")
endif()
message(STATUS "\n=============================================\n\n")


#-----------------------------------------------------------------------------
# Get submodules

execute_process(COMMAND git "submodule" "update" "--init" "--recursive" WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})


#-----------------------------------------------------------------------------
# Collect all binaries into bin subdirectory

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_CURRENT_BINARY_DIR}/bin)
set(LIBRARY_OUTPUT_PATH  ${CMAKE_CURRENT_BINARY_DIR}/lib)


#-----------------------------------------------------------------------------
# Compiler

if(BUILD_VALGRIND)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -O0 -g")
else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -Os")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -W -Wall -Wextra -pedantic -Werror -Wstrict-prototypes -Wmissing-prototypes -Werror-implicit-function-declaration -Wpointer-arith -std=gnu99 -ffunction-sections -fdata-sections -Wchar-subscripts -Wcomment -Wformat=2 -Wimplicit-int -Wmain -Wparentheses -Wsequence-point -Wreturn-type -Wswitch -Wtrigraphs -Wunused -Wuninitialized -Wunknown-pragmas -Wfloat-equal -Wundef -Wshadow -Wbad-function-cast -Wwrite-strings -Wsign-compare -Waggregate-return  -Wmissing-declarations -Wformat -Wmissing-format-attribute -Wno-deprecated-declarations -Wpacked -Wredundant-decls -Wnested-externs -Wmultichar -Wformat-nonliteral -Winit-self -Wformat-security -Wold-style-definition -Wmissing-include-dirs -Wswitch-default -Wattributes -Wcast-qual")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-all -Wno-unused-function -Wno-missing-field-initializers -Wno-long-long")

if(BUILD_TYPE STREQUAL "test")
    if(APPLE)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-deprecated-declarations")
        set(CMAKE_C_LINK_FLAGS "${CMAKE_C_LINK_FLAGS} -framework AppKit -framework IOKit")
        set(CMAKE_MACOSX_RPATH ON)
    endif()
endif()

if(NOT BUILD_TYPE STREQUAL "test")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mthumb -fdata-sections -fomit-frame-pointer -ffunction-sections -mlong-calls -mcpu=cortex-m4 -pipe -fno-strict-aliasing --param max-inline-insns-single=500 -D__SAM4S4A__ -DNDEBUG -DBOARD=USER_BOARD -DARM_MATH_CM4=true -DUDD_ENABLE -D_QTOUCH_ -Dscanf=iscanf -Dprintf=iprintf")
endif()


#-----------------------------------------------------------------------------
# Test coverage flags

if(BUILD_COVERAGE)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage")
    set(CMAKE_C_LINK_FLAGS "${CMAKE_C_LINK_FLAGS} -fprofile-arcs")
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
# Build 

message(STATUS "C Compiler ID:    ${CMAKE_C_COMPILER_ID}")
message(STATUS "C Flags:          ${CMAKE_C_FLAGS}")

add_subdirectory(src)

if(BUILD_TYPE STREQUAL "test")
    add_subdirectory(tests)
    add_test(NAME tests_unit COMMAND tests_unit)
    add_test(NAME tests_openssl COMMAND tests_openssl 200)
    add_test(NAME tests_api COMMAND tests_api)
    if(USE_SECP256K1_LIB)
        add_test(NAME tests_secp256k1 COMMAND tests_secp256k1 2)
    endif()
    enable_testing()

else()
    add_custom_command(
        OUTPUT ${MYPROJECT}.bin
        COMMAND ${CMAKE_SIZE} ${ELF}
        COMMAND ${CMAKE_OBJCOPY} -O binary ${ELF} ${MYPROJECT}.bin
        DEPENDS ${ELF}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin
        COMMENT "\nGenerating binary"
    )
    add_custom_target(binary_file ALL
        DEPENDS ${MYPROJECT}.bin ${ELF}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin
    )
    add_dependencies(binary_file ${ELF})
    
    if(BUILD_TYPE STREQUAL "bootloader")
        add_custom_command(
            OUTPUT ${MYPROJECT}.pad.bin
            COMMAND python ../../py/pad_boot_binary.py ${MYPROJECT}.bin ${MYPROJECT}.pad.bin
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin
            COMMENT "\nPadding binary"
        )
        add_custom_target(padded_file ALL
            DEPENDS ${MYPROJECT}.pad.bin
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin
        )
        add_dependencies(padded_file binary_file)
    endif()

endif()


#-----------------------------------------------------------------------------
# Clean 

set(removefiles "bin/*.* lib/*.*")
set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES "${removefiles}")
