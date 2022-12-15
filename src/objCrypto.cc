
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
}

__attribute__((visibility("default")))
ObjCryptoErr ObjCryptor::addKey( const KeyID keyID,
             const Key& key,
             const ObjCryptoAlg alg ){
  return ObjCryptoErr::None;
}

__attribute__((visibility("default")))
ObjCryptoErr ObjCryptor::seal(   KeyID keyID,
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


