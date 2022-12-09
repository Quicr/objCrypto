
cmake_minimum_required( VERSION 3.20 )

project( playCrypto C CXX)

set( CMAKE_CXX_STANDARD 17 )
set( CMAKE_C_STANDARD 17 )


set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD_REQUIRED ON)


add_subdirectory( contrib )
add_subdirectory( src ) 
add_subdirectory( test ) 

