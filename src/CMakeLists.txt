
# find_package(OpenSSL 1.1 REQUIRED)

include_directories(../contrib/boringssl/src/include  )

if ( ${OBJ_CRYPTO_USE_BORINGSSL} )
   set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DOBJ_CRYPTO_USE_BORINGSSL")
endif ()

if ( !MSVC )
# TODO - mst be better way to do this 
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=hidden -fno-common -fno-exceptions -fno-rtti")
endif()

configure_file (
    "${PROJECT_SOURCE_DIR}/include/objCrypto/objCryptoVersion.h.in"
    "${PROJECT_SOURCE_DIR}/include/objCrypto/objCryptoVersion.h"
)

# controll static shared with BUILD_SHARED_LIBS=ON.
add_library(
  objCrypto
)

target_sources( objCrypto 
  PRIVATE
  objCrypto.cc
  aes-ctr.cc 
  aes-gcm.cc )
 
set_target_properties( objCrypto PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties( objCrypto PROPERTIES SOVERSION 0)
set_target_properties( objCrypto PROPERTIES POSITION_INDEPENDENT_CODE ON)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if ( ${OBJ_CRYPTO_USE_BORINGSSL} )
   target_link_libraries( objCrypto PRIVATE crypto )
endif ()

target_include_directories( objCrypto PUBLIC ${PROJECT_SOURCE_DIR}/include )

set_target_properties( objCrypto PROPERTIES PUBLIC_HEADER
 "${PROJECT_SOURCE_DIR}/include/objCrypto/objCrypto.h;${PROJECT_SOURCE_DIR}/include/objCrypto/objCryptoVersion.h" ) 

install(TARGETS objCrypto 
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/objCrypto )


