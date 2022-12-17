
# find_package(OpenSSL 1.1 REQUIRED)


add_executable( testTest1
    testTest1.cc
)
add_test( NAME testTest1a
               COMMAND testTest1 0 )
add_test( NAME testTest1b
               COMMAND testTest1 1 2 )
set_tests_properties( testTest1b PROPERTIES WILL_FAIL TRUE)



add_executable ( testAes128CtrIv
    testAes128CtrIv.cc
)
target_link_libraries( testAes128CtrIv PRIVATE objCrypto )
add_test( NAME testAes128CtrIv
               COMMAND testAes128CtrIv  )


add_executable ( testAes128CtrNonce
    testAes128CtrNonce.cc
)
target_link_libraries( testAes128CtrNonce PRIVATE objCrypto )
add_test( NAME testAes128CtrNonce
               COMMAND testAes128CtrNonce  )
