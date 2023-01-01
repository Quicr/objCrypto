## Key management 

Keys are identified by a number ID called a keyID. The addKey method is
used to add new key along with the encryptions algorithm to the
ObjCryptor. The eraseKey method can remove a key and haveKey can be used
to check for the existence of a specific keyID.

When adding a key, an error is returned if the key is not the correct
size for the algorithm in use.

## Encryption algorithms 

The algorithms are identified with an enum such as AES_128_GCM_64. This
indicates the encryption algorithm is AES with 128 keys using the GCM
mode with a 64 bit authentication tag.  AES with 128 and 256 bits keys
are supported. A CTR mode is supported with 0 bit authentication tags
and GCM mode is supported with 64 or 128 bit authentication tags.

It is also worth noting that forgeries are often trivial when using the
CTR mode and zero bit tags.

## Encryption with seal 

The seal function is used to encrypt data. The functions is passed:

* keyID: used to find the key and algorithm to encrypt with that was
  previously set with addKey.
* nonce: 96 bytes data that is unique to this data. See below.
* plainText: The data to be encrypted
* authData: Any additional data that will not be encrypted but is
  included in the authentication tag
* tag: space to return the authentication tag. This must match the size
  for the crypto algorithm being used
* cipherText: space to return the encrypted results. This must be the
  same size as the plain text

It is critical that the nonce in unique for ever single thing encrypted
with the same key.  The library does not provide any protection from
reuse of the same nonce and the application using it must make sure this
never happens.

Error codes are returned if one of the input parameters is not the
correct size for the algorithm and key in use.

## Decryption with unseal 

The unseal method takes the following parameters: 

* keyID: used to find the key and algorithm to decrypt
* nonce: same 96 bit nonce used in the encrypt 
* cipherText: The data to be decrypted
* authData: The same additional data that was passed to the encryption
* tag: the tag that was output by the encryption 
* plainText: space to return the decrypted results. This must be the
  same size as the cipherText

If using an authentication tag, the error DecryptAuthFail will be
returned if the authentication does not match.

## Error codes 

The following error codes are used:

* None: Success, no error 
* DecryptAuthFail: The authentication failed in the decryption 
* InvalidKeyID: The keyID passed does not exist 
* UnkownCryptoAlg: An unknown crypto algorithm was used and the
  operation failed
* WrongKeySize: The key size does not match the crypto algorithm 
* WrongTagSize: The tag size does not match the crypto algorithm 
* WrongOutputDataSize: The size of vector for the output is not the same
  as the input size



