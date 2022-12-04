
# find_package(OpenSSL 1.1 REQUIRED)


add_executable( playCrypto
    test1.cc
)

# target_link_libraries( playCrypto PRIVATE OpenSSL::Crypto )

target_link_libraries( playCrypto ssl crypto )


