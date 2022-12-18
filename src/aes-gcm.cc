#include <iostream> // TODO REMOVE

#include <cassert>
#include <cstring>

#if defined( OBJ_CRYPTO_USE_BORINGSSL )
#include <openssl/cipher.h>
#endif

#if defined( __APPLE__ )
#include <CommonCrypto/CommonCryptor.h>


extern "C" {
CCCryptorStatus CCCryptorGCM(
	CCOperation 	op,				/* kCCEncrypt, kCCDecrypt */
	CCAlgorithm		alg,
	const void 		*key,			/* raw key material */
	size_t 			keyLength,	
	const void 		*iv,
	size_t 			ivLen,
	const void 		*aData,
	size_t 			aDataLen,
	const void 		*dataIn,
	size_t 			dataInLength,
  	void 			*dataOut,
	const void 		*tag,
	size_t 			*tagLength);
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
  
  assert( tag.size() >= 128/8 );
 
  size_t tagLen=tag.size();
  std::cout << "tag sizde encrypt in = "<< tagLen << std::endl;

  CCCryptorStatus status =  CCCryptorGCM( kCCEncrypt, // CCOperation op,
                                          kCCAlgorithmAES128, //CCAlgorithm alg,
                                          key.data(), key.size(), // const void *key, size_t keyLength,
                                          iv.data(), iv.size() , // const void *iv,  size_t 			ivLen,
                                          authData.data(), authData.size(), //const void  	*aData,//size_t 	aDataLen,
                                          plainText.data(), plainText.size(), // const void *dataIn, size_t dataInLength,
                                          cipherText.data(), // void *dataOut,
                                          tag.data(),  //   const void 		*tag,
                                          &tagLen // size_t 			*tagLength)
                                          );

  std::cout << "CCCrypto status = " <<  status << std::endl;

  assert( status != kCCParamError );
  assert( status == kCCSuccess );

  std::cout << "tag sizde encrypt out = "<< tagLen << std::endl;
  
  assert( tagLen <= 128/8 );
  
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
  assert( sizeof( key)  == 128/8 );

  assert( tag.size() >= 128/8 );
  
  size_t tagLen=tag.size();
  CCCryptorStatus status =  CCCryptorGCM( kCCDecrypt, // CCOperation op,
                                          kCCAlgorithmAES128, //CCAlgorithm alg,
                                          key.data(), key.size(), // const void *key, size_t keyLength,
                                          iv.data(), iv.size() , // const void *iv,  size_t 			ivLen,
                                          cipherText.data(), cipherText.size(), // const void *dataIn, size_t dataInLength,
                                          authData.data(), authData.size(), //const void  	*aData,//size_t 	aDataLen,
                                          plainText.data(), // void *dataOut,
                                          tag.data(),  //   const void 		*tag,
                                          &tagLen // size_t 			*tagLength)
                                          );
  
  assert( status == kCCSuccess );

  assert( tagLen <= 128/8 );
  
  
  return ObjCryptoErr::None;
}
#endif



#if defined( OBJ_CRYPTO_USE_BORINGSSL )
ObjCryptoErr ObjCrypto::aes128_gcm_encrypt(const Key128& key,
                                   const IV& iv,
                                   const std::vector<uint8_t>& plainText,
                                   const std::vector<uint8_t>& authData,
                                   std::vector<uint8_t>& tagData, 
                                   std::vector<uint8_t>& cipherText)
{
  /*
  EVP_CIPHER_CTX *ctx;
  
  assert( sizeof( key ) == 128/8 );
  assert( sizeof( iv ) == 128/8 );
  assert( plainText.size() == cipherText.size() );
  
  ctx = EVP_CIPHER_CTX_new();
  assert( ctx );
  
  int status;
  status = EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
  assert( status == 1 );
  
  status = EVP_EncryptInit_ex(ctx, NULL, NULL,
                              (const uint8_t*)key.data(),
                              (const uint8_t*)iv.data());
  assert( status == 1 );
  
  int moved=0;
  int cipherTextLen=0;
  status = EVP_EncryptUpdate(ctx,
                             (uint8_t*)cipherText.data(), &moved,
                             (const uint8_t *)plainText.data(), plainText.size());
  assert( status == 1 );
  cipherTextLen += moved;
  
  status = EVP_EncryptFinal_ex(ctx, (uint8_t *)&cipherText[cipherTextLen], &moved);
  assert( status == 1 );
  cipherTextLen += moved;
  
  assert( cipherTextLen == cipherText.size() );
  
  EVP_CIPHER_CTX_free(ctx);
  */
  
  return ObjCryptoErr::None;
}
#endif


#if defined( OBJ_CRYPTO_USE_BORINGSSL )
ObjCryptoErr ObjCrypto::aes128_gcm_decrypt(const Key128& key,
                                   const IV& iv,
                                   const std::vector<uint8_t>& cipherText,
                                   const std::vector<uint8_t>& authData,
                                   const std::vector<uint8_t>& tagData, 
                                   std::vector<uint8_t>& plainText )
{
  /*
  EVP_CIPHER_CTX *ctx;

  assert( sizeof( key ) == 128/8 );
  assert( sizeof( iv ) == 128/8 );
  assert( plainText.size() == cipherText.size() );
  
  ctx = EVP_CIPHER_CTX_new();
  assert( ctx );
  
  int status;
  status = EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
  assert( status == 1 );
  
  status = EVP_DecryptInit_ex(ctx, NULL, NULL,
                              (const uint8_t*)key.data(),
                              (const uint8_t*)iv.data());
  assert( status == 1 );
  
  int moved=0;
  int plainTextLen=0;
  status = EVP_DecryptUpdate(ctx,
                             (uint8_t*)plainText.data(), &moved,
                             (const uint8_t *)cipherText.data(), cipherText.size());
  assert( status == 1 );
  plainTextLen += moved;
  
  status = EVP_DecryptFinal_ex(ctx, (uint8_t *)&plainText[plainTextLen], &moved);
  assert( status == 1 );
  plainTextLen += moved;
  
  assert( plainTextLen == plainText.size() );
  
  EVP_CIPHER_CTX_free(ctx);
  */
  return ObjCryptoErr::None;
}
#endif
