
# find_package(OpenSSL 1.1 REQUIRED)

include_directories(../contrib/boringssl/src/include  )

if ( ${OBJ_CRYPTO_USE_BORINGSSL} )
   set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DOBJ_CRYPTO_USE_BORINGSSL")
endif ()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=hidden -fno-common -fno-exceptions -fno-rtti")

add_library(
  objCrypto
  SHARED
  objCrypto.cc
  aes-ctr.cc 
  aes-gcm.cc 
)

set_property(TARGET objCrypto PROPERTY POSITION_INDEPENDENT_CODE ON)

if ( ${OBJ_CRYPTO_USE_BORINGSSL} )
   target_link_libraries( objCrypto PRIVATE crypto )
endif ()

target_include_directories( objCrypto PUBLIC ${PROJECT_SOURCE_DIR}/include )


