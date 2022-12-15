#include <cassert>
#include <cstring>

#include <CommonCrypto/CommonCryptor.h>
#include <objCrypto/objCrypto.h>

#include "aes-ctr.h"

using namespace ObjCrypto;


ObjCryptoErr ObjCrypto::aes128_ctr_encrypt(const std::vector<char>& plainText,
                                const Key128& key,
                                const IV& iv, 
                                std::vector<uint8_t>& cipherText)
{
  CCCryptorRef cryptorRef;

  assert( plainText.size() == cipherText.size() );
  assert( sizeof( iv )  == sizeof( key )  );
  assert( sizeof( key)  == 128/8 );
  
  CCCryptorStatus status;
  status = CCCryptorCreateWithMode( kCCEncrypt,         // CCOperation
                                    kCCModeCTR,         // CCMode 
                                    kCCAlgorithmAES128, // CCAlgorithm
                                    ccNoPadding,        // CCPadding 
                                    iv.data(),          // const void *iv,
                                    key.data(),sizeof(key),// const void *key, size_t keyLength
                                    0,                  // const void *tweak,  
                                    0,                  // size_t tweakLength,
                                    0,                  // int numRounds,
                                    kCCModeOptionCTR_BE,// CCModeOptions 
                                    &cryptorRef);
  assert( status == kCCSuccess );

  size_t cipherTextLen=0;
  size_t moved=0;
  
  status = CCCryptorUpdate( cryptorRef,
                            plainText.data(), plainText.size(),// const void *dataIn, size_t dataInLength,
                            cipherText.data(), // void *dataOut,
                            cipherText.size(), // size_t dataOutAvailable,
                            &moved // size_t *dataOutMoved
                            );
  assert( status == kCCSuccess );
  cipherTextLen += moved;
 
  status = CCCryptorFinal( cryptorRef,
                           &cipherText[cipherTextLen], // void *dataOut,
                           cipherText.size()-cipherTextLen, // size_t dataOutAvailable,
                           &moved // size_t *dataOutMoved
                           );
  assert( status == kCCSuccess );
  cipherTextLen += moved;

  assert( cipherTextLen == cipherText.size() );
  
  status = CCCryptorRelease( cryptorRef);
  assert( status == kCCSuccess );
  
  return ObjCryptoErr::None;
}

    
ObjCryptoErr ObjCrypto::aes128_ctr_decrypt( const std::vector<uint8_t>& cipherText,
                                 const Key128& key,
                                 const IV& iv ,
                                 std::vector<char>& plainText )
{
  CCCryptorRef cryptorRef;

  assert( plainText.size() == cipherText.size() );
  assert( sizeof( iv )  ==sizeof( key )  );

  CCCryptorStatus status;
  status = CCCryptorCreateWithMode( kCCDecrypt,         // CCOperation
                                    kCCModeCTR,         // CCMode 
                                    kCCAlgorithmAES128, // CCAlgorithm
                                    ccNoPadding,        // CCPadding 
                                    iv.data(),                 // const void *iv,
                                    key.data(), sizeof(key),         // const void *key, size_t keyLength
                                    0,                  // const void *tweak,  
                                    0,                  // size_t tweakLength,
                                    0,                  // int numRounds,
                                    kCCModeOptionCTR_BE,// CCModeOptions 
                                    &cryptorRef);
  assert( status == kCCSuccess );

  size_t plainTextLen=0;
  size_t moved=0;
  status = CCCryptorUpdate( cryptorRef,
                            cipherText.data(), cipherText.size(),// const void *dataIn, size_t dataInLength,
                            plainText.data(), // void *dataOut,
                            plainText.size(), // size_t dataOutAvailable,
                            &moved // size_t *dataOutMoved
                            );
  assert( status == kCCSuccess );
  plainTextLen += moved;
 
  status = CCCryptorFinal( cryptorRef,
                           &plainText[plainTextLen], // void *dataOut,
                           plainText.size()-plainTextLen, // size_t dataOutAvailable,
                           &moved // size_t *dataOutMoved
                           );
  assert( status == kCCSuccess );
  plainTextLen += moved;

  assert( plainTextLen == plainText.size() );
  
  status = CCCryptorRelease( cryptorRef);
  assert( status == kCCSuccess );
  
  return ObjCryptoErr::None;
}
