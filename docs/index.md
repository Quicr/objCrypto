# Overview

The objCrypto library provides a C++ interface to encrypt and decrypt
objects.

An ObjCryptor object is created to keep track of all the keys being
used. Keys along with the encryption algorithm are added to the
ObjCryptor then the seal and unseal methods can be used to encrypt and
decrypt data. The encryption can aslo generate and authentication tag
that can be passed to the decryption so that the decryption can
authenticated the encrypted data has not been modified.

## Example 

There is an example program at 
https://github.com/Quicr/objCrypto/blob/main/example/objCryptoExampleA.cc 

