
# find_package(OpenSSL 1.1 REQUIRED)


include_directories(../contrib/boringssl/src/include)

add_executable( playCrypto
    test1.cc
)

# target_link_libraries( playCrypto PRIVATE OpenSSL::Crypto )

target_link_libraries( playCrypto PRIVATE crypto )



