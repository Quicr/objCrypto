
#include <objCrypto/objCrypto.h>

#include <openssl/cipher.h>

#include "aes-ctr.h"

using namespace ObjCrypto;

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
ObjCryptoErr ObjCryptor::removeKey( KeyID keyID ){
   assert( haveKey( keyID ) );

   keyMap.erase( keyID );
   
   return ObjCryptoErr::None;
}

__attribute__((visibility("default")))
bool ObjCryptor::haveKey( KeyID keyID ){
  if (keyMap.find(keyID) != keyMap.end()) {
    return true;
  }
  return false;
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
  default:
    assert(0);
    break;
  }
  
  keyMap.insert( std::make_pair( keyID , key) );
  return ObjCryptoErr::None;
}

__attribute__((visibility("default")))
ObjCryptoErr ObjCryptor::seal( KeyID keyID,
                               const Nonce& nonce,
                               const std::vector<char>& plainText,
                               std::vector<uint8_t>& cipherText  ){
  assert( haveKey( keyID ) );
  const Key& key = keyMap.at( keyID );

  assert( plainText.size() == cipherText.size() );
  
  switch (key.first) {
  case ObjCryptoAlg::AES128_CTR: {
    assert(  std::holds_alternative<Key128>( key.second ) );
    Key128 key128 = std::get<Key128>(  key.second );
     assert( sizeof(key128) == 128/8 );
     
    IV iv = {0,0};
    assert( sizeof( iv ) > sizeof( nonce ) );
    std::memcpy( iv.data(), nonce.data(), sizeof( nonce ) );
    assert( sizeof(iv) == 128/8 );
    
    aes128_ctr_encrypt( plainText, key128, iv,  cipherText);
    
    break;
  }
  case ObjCryptoAlg::AES128_GCM:
  case ObjCryptoAlg::AES256_GCM:
  case ObjCryptoAlg::AES256_CTR: 
  default:
    assert(0);
    break;
  }
   
  return ObjCryptoErr::None;
}

__attribute__((visibility("default")))
ObjCryptoErr ObjCryptor::unseal( KeyID keyID,
                                 const Nonce& nonce,
                                 const std::vector<uint8_t>& cipherText, 
                                 std::vector<char>& plainText ){
   assert( haveKey( keyID ) );
  const Key& key = keyMap.at( keyID );

  assert( cipherText.size() ==  plainText.size());
  
  switch (key.first) {
  case ObjCryptoAlg::AES128_CTR: {
    assert(  std::holds_alternative<Key128>( key.second ) );
    Key128 key128 = std::get<Key128>(  key.second );
    assert( sizeof(key128) == 128/8 );
     
    IV iv = {0,0};
    assert( sizeof( iv ) > sizeof( nonce ) );
    std::memcpy( iv.data(), nonce.data(), sizeof( nonce ) );
    assert( sizeof(iv) == 128/8 );
 
    aes128_ctr_decrypt( cipherText, key128, iv, plainText );
    break;
  }
  case ObjCryptoAlg::AES128_GCM:
  case ObjCryptoAlg::AES256_GCM:
  case ObjCryptoAlg::AES256_CTR: 
  default:
    assert(0);
    break;
  }
   
  return ObjCryptoErr::None;
}


