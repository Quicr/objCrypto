
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



add_executable ( testAesCtr
    testAesCtr.cc
)
target_link_libraries( testAesCtr PRIVATE objCrypto doctest::doctest  )
add_test( NAME testAesCtr
               COMMAND testAesCtr  )



add_executable ( testAesGcm
    testAesGcm.cc
)
target_link_libraries( testAesGcm PRIVATE objCrypto doctest::doctest  )
add_test( NAME testAesGcm
               COMMAND testAesGcm  )




add_executable ( testSpeedCtr
    testSpeedCtr.cc
)
target_link_libraries( testSpeedCtr PRIVATE objCrypto  doctest::doctest )


add_executable ( testSpeedGcm
    testSpeedGcm.cc
)
target_link_libraries( testSpeedGcm PRIVATE objCrypto doctest::doctest  )

