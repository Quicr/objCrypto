
# find_package(OpenSSL 1.1 REQUIRED)
# find_package(doctest REQUIRED)


add_executable( testTest
    testTest.cc
)
target_link_libraries( testTest PRIVATE doctest::doctest )
add_test( NAME testTest
               COMMAND testTest )



add_executable( testVersion
    testVersion.cc
)
target_link_libraries( testVersion PRIVATE objCrypto doctest::doctest ) 
add_test( NAME testVersion
               COMMAND testVersion )



add_executable ( testNulNul
    testNulNul.cc
)
target_link_libraries( testNulNul PRIVATE objCrypto doctest::doctest  )
add_test( NAME testNulNul
               COMMAND testNulNul  )



add_executable ( testAes128Ctr
    testAes128Ctr.cc
)
target_link_libraries( testAes128Ctr PRIVATE objCrypto doctest::doctest  )
add_test( NAME testAes128Ctr
               COMMAND testAes128Ctr  )



add_executable ( testAes128Gcm
    testAes128Gcm.cc
)
target_link_libraries( testAes128Gcm PRIVATE objCrypto doctest::doctest  )
add_test( NAME testAes128Gcm
               COMMAND testAes128Gcm  )




add_executable ( testSpeedCtr
    testSpeedCtr.cc
)
target_link_libraries( testSpeedCtr PRIVATE objCrypto  doctest::doctest )


add_executable ( testSpeedGcm
    testSpeedGcm.cc
)
target_link_libraries( testSpeedGcm PRIVATE objCrypto doctest::doctest  )

