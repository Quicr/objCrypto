
# find_package(OpenSSL 1.1 REQUIRED)


add_executable( testTest1
    testTest1.cc
)
target_link_libraries( testTest1 PRIVATE doctest )
add_test( NAME testTest1a
               COMMAND testTest1 )



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



add_executable ( testAes128GcmIv
    testAes128GcmIv.cc
)
target_link_libraries( testAes128GcmIv PRIVATE objCrypto )
add_test( NAME testAes128GcmIv
               COMMAND testAes128GcmIv  )


add_executable ( testSpeedCtr
    testSpeedCtr.cc
)
target_link_libraries( testSpeedCtr PRIVATE objCrypto )


add_executable ( testSpeedGcm
    testSpeedGcm.cc
)
target_link_libraries( testSpeedGcm PRIVATE objCrypto )

