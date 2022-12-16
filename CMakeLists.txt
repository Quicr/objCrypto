
cmake_minimum_required( VERSION 3.20 )

project( playCrypto C CXX)

set( CMAKE_CXX_STANDARD 17 )
set( CMAKE_C_STANDARD 17 )


set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD_REQUIRED ON)

if ( {APPLE} )
   set( OBJ_CRYPTO_USE_BORINGSSL False CACHE BOOL "use boring SSL for crypto"  )
else ()
   set( OBJ_CRYPTO_USE_BORINGSSL True CACHE BOOL "use boring SSL for crypto"  )
endif ()

message( "OBJ_CRYPTO_USE_BORINGSSL is set to ${OBJ_CRYPTO_USE_BORINGSSL} " )

add_subdirectory( contrib )
add_subdirectory( src ) 
add_subdirectory( test ) 

