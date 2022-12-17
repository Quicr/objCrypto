
# find_package(OpenSSL 1.1 REQUIRED)

add_executable( testObjCrypto1
    testObjCrypto1.cc
)
target_link_libraries( testObjCrypto1 PRIVATE objCrypto )

add_executable( testTest1
    testTest1.cc
)

add_test( NAME testTest1a
               COMMAND testTest1 0 )

add_test( NAME testTest1b
               COMMAND testTest1 1 2 )

set_tests_properties( testTest1b PROPERTIES WILL_FAIL TRUE)


add_executable ( testAES128CTR
    testAES128CTR.cc
)
target_link_libraries( testAES128CTR PRIVATE objCrypto )
add_test( NAME testAES128CTR
               COMMAND testAES128CTR  )
