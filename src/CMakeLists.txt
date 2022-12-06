
# find_package(OpenSSL 1.1 REQUIRED)


include_directories(../contrib/boringssl/src/include)

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


