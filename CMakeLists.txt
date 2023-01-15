# SPDX-FileCopyrightText: Copyright (c) 2022 The ObjCrypto Project Authors 
# SPDX-License-Identifier: BSD-2-Clause


cmake_minimum_required( VERSION 3.13..3.25 )


if ( NOT DEFINED ANDROID_PLATFORM )
  if ( ${APPLE}  )
    if( NOT ${OBJ_CRYPTO_USE_BORINGSSL} )
      if ( NOT DEFINED CMAKE_OSX_ARCHITECTURES )
        set( CMAKE_OSX_ARCHITECTURES "arm64;x86_64" CACHE STRING "OSX archs")
      endif()
    endif()
  endif ()
endif ()


project( objCrypto
            VERSION 0.1.2
            DESCRIPTION "C++ Library to encrypt and decrypt objects"
            HOMEPAGE_URL "https://github.com/fluffy/objCrypto"
            LANGUAGES C CXX)

if ( ${APPLE} )
   set( OBJ_CRYPTO_USE_BORINGSSL False CACHE BOOL "use BoringSSL SSL crypto"  )
else ()
   set( OBJ_CRYPTO_USE_BORINGSSL True CACHE BOOL "use BoringSSL for crypto"  )
endif ()

if ( WIN32 )
   set( BUILD_TESTS False CACHE BOOL "build tests"  )
else ()
   set( BUILD_TESTS True CACHE BOOL "build tests"  )
endif ()

set( BUILD_SHARED_LIBS True CACHE BOOL "build as shared library"  )

option( BUILD_TESTS "Build test programs" ON)
option( OBJ_CRYPTO_USE_BORINGSSL "Use BoringSSL for crypto" )
option( BUILD_SHARED_LIBS "Build as shared library" )


set( CMAKE_CXX_STANDARD 17 )
set( CMAKE_C_STANDARD 17 )
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD_REQUIRED ON)

message( "OBJ_CRYPTO_USE_BORINGSSL is set to ${OBJ_CRYPTO_USE_BORINGSSL} " )
message( "BUILD_TESTS  is set to ${BUILD_TESTS} " ) 
message( "BUILD_SHARED_LIBS is set to ${BUILD_SHARED_LIBS} " ) 
message( "CMAKE_OSX_ARCHITECTURES is set to ${CMAKE_OSX_ARCHITECTURES} " )

include(CTest)


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

add_subdirectory( contrib )
add_subdirectory( src )

if( BUILD_TESTS )
    add_subdirectory( test )  
    add_subdirectory( example )  
endif()

include(GNUInstallDirs)

install(FILES ${CMAKE_BINARY_DIR}/objCrypto.pc
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig)


