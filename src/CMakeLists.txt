
# find_package(OpenSSL 1.1 REQUIRED)


include_directories(../contrib/boringssl/src/include  )

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=hidden -fno-common -fno-exceptions -fno-rtti")

add_library(
  objCrypto
  SHARED
  objCrypto.cc
  aes-ctr.cc
) 
target_link_libraries( objCrypto PRIVATE crypto )
target_include_directories( objCrypto PUBLIC ${PROJECT_SOURCE_DIR}/include )




add_executable( test1 
    test1.cc
)
target_link_libraries( test1 PRIVATE crypto )


add_executable( test2
    test2.cc
)
target_link_libraries( test2 PRIVATE system )


add_executable( test3
    test3.cc
)
target_link_libraries( test3 PRIVATE system )


add_executable( test4
    test4.cc
)
target_link_libraries( test4 PRIVATE crypto )


add_executable( test5 
    test5.cc
)
target_link_libraries( test5 PRIVATE crypto )
