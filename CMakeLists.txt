cmake_minimum_required( VERSION 3.13..3.25 )

project( playCrypto
            VERSION 0.1.1
            DESCRIPTION "C++ Libraary to encrypt and decrypt objects"
            HOMEPAGE_URL "https://github.com/fluffy/objCrypto"
            LANGUAGES C CXX)


if ( ${APPLE} )
   set( OBJ_CRYPTO_USE_BORINGSSL False CACHE BOOL "use boring SSL for crypto"  )
else ()
   set( OBJ_CRYPTO_USE_BORINGSSL True CACHE BOOL "use boring SSL for crypto"  )
endif ()

option( BUILD_TESTS "Build test programs" ON)
option( OBJ_CRYPTO_USE_BORINGSSL "Use Booringssl for crypto" )


set( CMAKE_CXX_STANDARD 17 )
set( CMAKE_C_STANDARD 17 )


set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD_REQUIRED ON)

message( "OBJ_CRYPTO_USE_BORINGSSL is set to ${OBJ_CRYPTO_USE_BORINGSSL} " )
message( "BUILD_TESTS  is set to ${BUILD_TESTS} " )

include(CTest)


find_package(Git QUIET)

if(GIT_FOUND AND EXISTS "${PROJECT_SOURCE_DIR}/.git")
    execute_process(COMMAND ${GIT_EXECUTABLE} submodule update --init --recursive
                    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                    RESULT_VARIABLE GIT_SUBMOD_RESULT)
    if(NOT GIT_SUBMOD_RESULT EQUAL "0")
        message(FATAL_ERROR "git submodule update --init --recursive failed with ${GIT_SUBMOD_RESULT}, please checkout submodules")
    endif()
endif()



add_subdirectory( contrib )
add_subdirectory( src )

if( BUILD_TESTS )
    add_subdirectory( test ) 
endif()
