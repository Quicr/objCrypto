
doctest is at v2.4.9 from Jun 18, 2022

BoringSSL is at  master from Dec  8, 2022 

Have a read of boringssl-crypto/src/INCORPORATING.md to see how to update 
cd contrib/boringssl-crypto/src ; git checkout chromium-5414 ; 
cd contrib/boringssl-crypto; 
rm -rf apple-* linux-* win-* CMakeLists.txt crypto_test_data.cc err_data.c
python3 src/util/generate_build_files.py cmake
edit cmake to remove ssl and bssl targets
edit CMAKEE for crypto lib to be OBJECT  and add 

add follosing right after project 
set( BUILD_SHARED_LIB TRUE )
if ( WIN32 )
   set(  OPENSSL_NO_ASM TRUE )
endif()
git add 
git push the boringssl-crpto lib 
