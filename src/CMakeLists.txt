# SPDX-FileCopyrightText: Copyright (c) 2022 The ObjCrypto Project Authors 
# SPDX-License-Identifier: BSD-2-Clause

if ( ${OBJ_CRYPTO_USE_BORINGSSL} )
   include_directories( ../contrib/boringssl-crypto/src/include  )
   set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DOBJ_CRYPTO_USE_BORINGSSL")
endif()

if ( !MSVC )
# TODO - mst be better way to do this 
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=hidden -fno-common -fno-exceptions -fno-rtti")
endif()

configure_file (
    "${PROJECT_SOURCE_DIR}/include/objCrypto/version.h.in"
    "${PROJECT_SOURCE_DIR}/include/objCrypto/version.h"
)

add_library( objCrypto )
target_sources( objCrypto PRIVATE aes-ctr.cc aes-ctr.h aes-gcm.cc aes-gcm.h objCrypto.cc)

# Lots of warnings as errors 
if (MSVC) 
    add_compile_options(/W4 /WX) 
else() 
    add_compile_options(-Wall -Wextra -pedantic -Werror) 
endif() 


set_target_properties( objCrypto PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties( objCrypto PROPERTIES SOVERSION 0)
set_target_properties( objCrypto PROPERTIES POSITION_INDEPENDENT_CODE ON)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if ( ${OBJ_CRYPTO_USE_BORINGSSL} )
   target_link_libraries( objCrypto PRIVATE crypto )
   if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
     target_link_libraries( objCrypto PRIVATE pthread )
   endif ()
endif ()

target_include_directories( objCrypto PUBLIC ${PROJECT_SOURCE_DIR}/include )

set_target_properties( objCrypto PROPERTIES PUBLIC_HEADER
 "${PROJECT_SOURCE_DIR}/include/objCrypto/objCrypto.h;${PROJECT_SOURCE_DIR}/include/objCrypto/objCryptoVersion.h" ) 

if( ${OBJ_CRYPTO_INSTALL})
    install(TARGETS objCrypto 
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/objCrypto )
endif()
