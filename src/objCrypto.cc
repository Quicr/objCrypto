
#include <objCrypto/objCrypto.h>


#include <openssl/cipher.h>

// __declspec(dllimport)

 __attribute__((visibility("default")))  int callTheWrap( int a, int b ) {

    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    if ( !ctx ) { assert(0); }

  return a+b;
}


using namespace ObjCrypto;

__attribute__((visibility("default")))
ObjCryptor::ObjCryptor( ){
}

__attribute__((visibility("default")))
ObjCryptor::~ObjCryptor( ){
  keyMap.clear();
}

__attribute__((visibility("default")))
ObjCryptoErr ObjCryptor::addKey( const KeyID keyID,
             const Key& key ){
  
  switch (key.first) {
  case ObjCryptoAlg::AES128_GCM:
  case ObjCryptoAlg::AES128_CTR: {
    assert(  std::holds_alternative<Key128>( key.second ) );
    break;
  }
  case ObjCryptoAlg::AES256_GCM:
  case ObjCryptoAlg::AES256_CTR: {
    assert(  std::holds_alternative<Key256>( key.second ) );
    break;
  }
  default: {
    assert(0);
    break;
  }
  }
  
  keyMap.insert( std::make_pair( keyID , key) );
  return ObjCryptoErr::None;
}

__attribute__((visibility("default")))
ObjCryptoErr ObjCryptor::seal( KeyID keyID,
                     const Nonce& nonce,
                     char* plainText, int textLen,
                     unsigned char* cipherText ){
  
  return ObjCryptoErr::None;
}

__attribute__((visibility("default")))
ObjCryptoErr ObjCryptor::unseal( KeyID keyID,
                     const Nonce& nonce,
                     unsigned char* cipherText, int textLen,
                     char* plainText ){
  return ObjCryptoErr::None;
}


