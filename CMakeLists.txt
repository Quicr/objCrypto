
cmake_minimum_required( VERSION 3.20 )

project( playCrypto C CXX)


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

add_subdirectory( contrib )
add_subdirectory( src )

if( BUILD_TESTS )
    add_subdirectory( test ) 
endif()
