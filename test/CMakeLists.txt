
# find_package(OpenSSL 1.1 REQUIRED)
# find_package(doctest REQUIRED)


add_executable( testTest1
    testTest1.cc
)
target_link_libraries( testTest1 PRIVATE doctest::doctest )
add_test( NAME testTest1a
               COMMAND testTest1 )



add_executable( testVersion
    testVersion.cc
)
target_link_libraries( testVersion PRIVATE objCrypto doctest::doctest ) 
add_test( NAME testVersion
               COMMAND testVersion )



add_executable ( testAes128CtrIv
    testAes128CtrIv.cc
)
target_link_libraries( testAes128CtrIv PRIVATE objCrypto doctest::doctest )  
add_test( NAME testAes128CtrIv
               COMMAND testAes128CtrIv  )


add_executable ( testAes128CtrNonce
    testAes128CtrNonce.cc
)
target_link_libraries( testAes128CtrNonce PRIVATE objCrypto doctest::doctest  )
add_test( NAME testAes128CtrNonce
               COMMAND testAes128CtrNonce  )



add_executable ( testAes128GcmIv
    testAes128GcmIv.cc
)
target_link_libraries( testAes128GcmIv PRIVATE objCrypto doctest::doctest  )
add_test( NAME testAes128GcmIv
               COMMAND testAes128GcmIv  )


add_executable ( testSpeedCtr
    testSpeedCtr.cc
)
target_link_libraries( testSpeedCtr PRIVATE objCrypto  doctest::doctest )


add_executable ( testSpeedGcm
    testSpeedGcm.cc
)
target_link_libraries( testSpeedGcm PRIVATE objCrypto doctest::doctest  )

