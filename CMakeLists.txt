# SPDX-FileCopyrightText: Copyright (c) 2022 The ObjCrypto Project Authors 
# SPDX-License-Identifier: BSD-2-Clause

cmake_minimum_required(VERSION 3.13)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 11)  # to move this to 17, need min CMake 3.21 
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD_REQUIRED ON)

project( objCrypto
            VERSION 0.1.2
            DESCRIPTION "C++ Library to encrypt and decrypt objects"
            HOMEPAGE_URL "https://github.com/Quicr/objCrypto"
            LANGUAGES C CXX)


if ( ${APPLE} )
   set( OBJ_CRYPTO_USE_BORINGSSL False CACHE BOOL "use BoringSSL SSL crypto"  )
else ()
   set( OBJ_CRYPTO_USE_BORINGSSL True CACHE BOOL "use BoringSSL for crypto"  )
endif ()

# ObjCrypto compiler options
option( OBJ_CRYPTO_USE_BORINGSSL "Use BoringSSL for crypto" )
option( OBJ_CRYPTO_BUILD_TESTS "Build test programs" ON )
option( OBJ_CRYPTO_BUILD_SHARED "Build as dynamic library" ON )
option( OBJ_CRYPTO_INSTALL "Install library to system" ON )

message( "OBJ_CRYPTO_USE_BORINGSSL is set to ${OBJ_CRYPTO_USE_BORINGSSL}" )
message( "OBJ_CRYPTO_BUILD_TESTS  is set to ${OBJ_CRYPTO_BUILD_TESTS}" ) 
message( "OBJ_CRYPTO_BUILD_SHARED is set to ${OBJ_CRYPTO_BUILD_SHARED}" ) 
message( "OBJ_CRYPTO_INSTALL is set to ${OBJ_CRYPTO_INSTALL}" )

set(BUILD_SHARED_LIBS ${OBJ_CRYPTO_BUILD_SHARED})

#find_package(Git QUIET)
#
#if(GIT_FOUND AND EXISTS "${PROJECT_SOURCE_DIR}/.git")
#   execute_process(COMMAND ${GIT_EXECUTABLE} submodule update --init --recursive
#                    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
#                    RESULT_VARIABLE GIT_SUBMOD_RESULT)
#   if(NOT GIT_SUBMOD_RESULT EQUAL "0")
#        message(FATAL_ERROR "git submodule update --init --recursive failed with ${GIT_SUBMOD_RESULT}, please checkout submodules")
#    endif()
#endif()

configure_file(objCrypto.pc.in objCrypto.pc @ONLY)

# Build directories
include_directories( include )
add_subdirectory( contrib )
add_subdirectory( src )

# Test directories
if ( OBJ_CRYPTO_BUILD_TESTS )
    include(CTest)
    add_subdirectory( test )
    add_subdirectory( example )
endif()

# Install
if ( OBJ_CRYPTO_INSTALL )
    include(GNUInstallDirs)

    install(FILES ${CMAKE_BINARY_DIR}/objCrypto.pc
        DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig)
endif()
