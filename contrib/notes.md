
doctest is at v2.4.9 from Jun 18, 2022

BoringSSL is at  fips-20220613 

Have a read of boringssl-crypto/src/INCORPORATING.md to see how to update 
cd boringssl-crypto/src ; git checkout fips-20220613 ; 
cd boringssl-crypto; python3 src/util/generate_build_files.py cmake
edit cmake to remove ssl and bssl targets

