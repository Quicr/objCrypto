//#include <iostream> // TODO REMOVE

#include <cassert>
#include <cstring>

#if defined( OBJ_CRYPTO_USE_BORINGSSL )
#include <openssl/cipher.h>
#endif

#if defined( __APPLE__ )
#include <CommonCrypto/CommonCryptor.h>


extern "C" {

// See https://opensource.apple.com/source/CommonCrypto/CommonCrypto-60165/include/Private/CommonCryptorSPI.h

CCCryptorStatus CCCryptorGCMOneshotEncrypt(CCAlgorithm alg, const void  *key,    size_t keyLength, /* raw key material */
                                        const void  *iv,     size_t ivLength,
                                        const void  *aData,  size_t aDataLength,
                                        const void  *dataIn, size_t dataInLength,
                                        void 	    *cipherOut,
                                        void        *tagOut, size_t tagLength) __attribute__((__warn_unused_result__))
API_AVAILABLE(macos(10.13), ios(11.0));

CCCryptorStatus CCCryptorGCMOneshotDecrypt(CCAlgorithm alg, const void  *key,    size_t keyLength,
                                       const void  *iv,     size_t ivLen,
                                       const void  *aData,  size_t aDataLen,
                                       const void  *dataIn, size_t dataInLength,
                                       void 	   *dataOut,
                                       const void  *tagIn,  size_t tagLength) __attribute__((__warn_unused_result__))
  API_AVAILABLE(macos(10.13), ios(11.0));
}

#endif

#include <objCrypto/objCrypto.h>

#include "aes-gcm.h"

using namespace ObjCrypto;


#if defined( __APPLE__ ) && !defined( OBJ_CRYPTO_USE_BORINGSSL )
ObjCryptoErr ObjCrypto::aes128_gcm_encrypt( const Key128& key,
                                 const IV& iv,
                                 const std::vector<uint8_t>& plainText,
                                 const std::vector<uint8_t>& authData,
                                 std::vector<uint8_t>& tag, 
                                 std::vector<uint8_t>& cipherText )
{
  CCCryptorRef cryptorRef;

  assert( plainText.size() == cipherText.size() );
  assert( sizeof( iv )  == sizeof( key )  );
  assert( sizeof( key)  == 128/8 );

  assert( plainText.size() > 0 ); // apple gives error if it is zero size

  assert( tag.size() >= 8 );
  assert( tag.size() <= 16 );

  
  CCCryptorStatus status =
    CCCryptorGCMOneshotEncrypt( kCCAlgorithmAES128, 
                                key.data(), key.size(),
                                iv.data(), iv.size() , 
                                authData.data(), authData.size(), 
                                plainText.data(), plainText.size(),
                                cipherText.data(), 
                                tag.data(), tag.size() );
  
  //std::cout << "CCCrypto status = " <<  status << std::endl;
  
  assert( status != kCCParamError );
  assert( status == kCCSuccess );
 
  return ObjCryptoErr::None;
}
#endif

    
#if defined( __APPLE__ ) && !defined( OBJ_CRYPTO_USE_BORINGSSL )
ObjCryptoErr ObjCrypto::aes128_gcm_decrypt( const Key128& key,
                                   const IV& iv,
                                   const std::vector<uint8_t>& cipherText,
                                   const std::vector<uint8_t>& authData,
                                   const std::vector<uint8_t>& tag, 
                                   std::vector<uint8_t>& plainText )
{
 CCCryptorRef cryptorRef;

  assert( plainText.size() == cipherText.size() );
  assert( sizeof( iv )  == sizeof( key )  );
  assert( sizeof( key )  == 128/8 );

  assert( tag.size() >= 8 );
  assert( tag.size() <= 16 );
 
  
  CCCryptorStatus status =
    CCCryptorGCMOneshotDecrypt( kCCAlgorithmAES128, 
                                key.data(), key.size(), 
                                iv.data(), iv.size() , 
                                authData.data(), authData.size(), 
                                cipherText.data(), cipherText.size(), 
                                plainText.data(), 
                                tag.data(), tag.size() );

  //std::cout << "CCCrypto decrypt status = " <<  status << std::endl;
  if ( status == kCCUnspecifiedError ) {
    return ObjCryptoErr::DecryptAuthFail;
  }

  assert( status == kCCSuccess );

  
  return ObjCryptoErr::None;
}
#endif



#if defined( OBJ_CRYPTO_USE_BORINGSSL )
ObjCryptoErr ObjCrypto::aes128_gcm_encrypt(const Key128& key,
                                   const IV& iv,
                                   const std::vector<uint8_t>& plainText,
                                   const std::vector<uint8_t>& authData,
                                   std::vector<uint8_t>& tag, 
                                   std::vector<uint8_t>& cipherText)
{
  EVP_CIPHER_CTX *ctx;

  int moved=0;
  int cipherTextLen=0;

  ctx = EVP_CIPHER_CTX_new();
  assert( ctx );
  
  int ret;
  ret = EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
  assert( ret == 1 );
  
  // set IV length ( default is 96 ) 
  ret =  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL);
  assert( ret == 1 );

  ret = EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), iv.data());
  assert( ret == 1 );

  // do the AAD Data 
  ret = EVP_EncryptUpdate(ctx, NULL, &moved, authData.data(), authData.size()); // what is moved here 
  assert( ret == 1 );
  //assert( moved == 0 ); 

  ret = EVP_EncryptUpdate(ctx, cipherText.data(), &moved, plainText.data(), plainText.size() );
  assert( ret == 1 );
  cipherTextLen += moved;

  ret = EVP_EncryptFinal_ex(ctx, &cipherText[cipherTextLen], &moved);
  assert( ret == 1 );
  cipherTextLen += moved;

  assert( cipherTextLen == cipherText.size() );
  
  ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data() ); // TODO - check tag.size is what needed
  assert( ret == 1 );

  EVP_CIPHER_CTX_free(ctx);
 
  return ObjCryptoErr::None;
}
#endif


#if defined( OBJ_CRYPTO_USE_BORINGSSL )
ObjCryptoErr ObjCrypto::aes128_gcm_decrypt(const Key128& key,
                                   const IV& iv,
                                   const std::vector<uint8_t>& cipherText,
                                   const std::vector<uint8_t>& authData,
                                   const std::vector<uint8_t>& tag, 
                                   std::vector<uint8_t>& plainText )
{
  EVP_CIPHER_CTX *ctx;

  int moved=0;
  int plainTextLen=0;

  ctx = EVP_CIPHER_CTX_new();
  assert( ctx );
  
  int ret;
  ret = EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
  assert( ret == 1 );
  
  // set IV length ( default is 96 ) 
  ret =  EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL);
  assert( ret == 1 );

  ret = EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), iv.data());
  assert( ret == 1 );

  // do the AAD Data 
  ret = EVP_DecryptUpdate(ctx, NULL, &moved, authData.data(), authData.size()); // what is moved here 
  assert( ret == 1 );
  //assert( moved == 0 ); 

  ret = EVP_DecryptUpdate(ctx, plainText.data(), &moved, cipherText.data(), cipherText.size() );
  assert( ret == 1 );
  plainTextLen += moved;

  // do tag 
  ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), (void*) tag.data()); // TODO check tag size 
  assert( ret == 1 );
      
  
  ret = EVP_DecryptFinal_ex(ctx, &plainText[plainTextLen], &moved);
  
  EVP_CIPHER_CTX_free(ctx);

  if ( ret == 0 ) {
    return ObjCryptoErr::DecryptAuthFail;
    plainText.clear();
  }
  
  assert( ret == 1 );
  plainTextLen += moved;

  assert( plainTextLen == plainText.size() );
    
  return ObjCryptoErr::None;
}
#endif
