
# find_package(OpenSSL 1.1 REQUIRED)

add_executable( testObjCrypto1
    testObjCrypto1.cc
)
target_link_libraries( testObjCrypto1 PRIVATE objCrypto )
