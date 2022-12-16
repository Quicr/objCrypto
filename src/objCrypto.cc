
#include <cassert>
#include <cstring>
 
#include <objCrypto/objCrypto.h>

#include <openssl/cipher.h>

#include "aes-ctr.h"

using namespace ObjCrypto;


__attribute__((visibility("default")))
ObjCryptor::ObjCryptor( ){
}


__attribute__((visibility("default")))
ObjCryptor::~ObjCryptor( ){
  keyInfoMap.clear();
}


__attribute__((visibility("default")))
ObjCryptoErr ObjCryptor::removeKey( KeyID keyID ){
   assert( haveKey( keyID ) );

   keyInfoMap.erase( keyID );
   
   return ObjCryptoErr::None;
}


__attribute__((visibility("default")))
bool ObjCryptor::haveKey( KeyID keyID ){
  if (keyInfoMap.find(keyID) != keyInfoMap.end()) {
    return true;
  }
  return false;
}


__attribute__((visibility("default")))
ObjCryptoErr ObjCryptor::addKey( const KeyID keyID,
             const KeyInfo& keyInfo ){
  
  switch (keyInfo.first) {
  case ObjCryptoAlg::AES128_GCM:
  case ObjCryptoAlg::AES128_CTR: {
    assert(  std::holds_alternative<Key128>( keyInfo.second ) );
    break;
  }
  case ObjCryptoAlg::AES256_GCM:
  case ObjCryptoAlg::AES256_CTR: {
    assert(  std::holds_alternative<Key256>( keyInfo.second ) );
    break;
  }
  default:
    assert(0);
    break;
  }
  
  keyInfoMap.insert( std::make_pair( keyID , keyInfo ) );
  return ObjCryptoErr::None;
}


__attribute__((visibility("default")))
ObjCryptoErr ObjCryptor::seal( KeyID keyID,
                               const Nonce& nonce,
                               const std::vector<char>& plainText,
                               std::vector<uint8_t>& cipherText  ){
  assert( haveKey( keyID ) );
  const KeyInfo& keyInfo = keyInfoMap.at( keyID );

  assert( plainText.size() == cipherText.size() );
           
  switch (keyInfo.first) {
  case ObjCryptoAlg::AES128_CTR: {
    assert(  std::holds_alternative<Key128>( keyInfo.second ) );
    Key128 key = std::get<Key128>(  keyInfo.second );
     
    IV iv = {0,0};
    assert( sizeof( iv ) > sizeof( nonce ) );
    std::memcpy( iv.data(), nonce.data(), sizeof( nonce ) );
    assert( sizeof(iv) == sizeof(key) );
    assert( plainText.size() <= ( sizeof(key) * (1<<24) ) );

    aes128_ctr_encrypt( plainText, key, iv,  cipherText);
    
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
  const KeyInfo& keyInfo = keyInfoMap.at( keyID );

  assert( cipherText.size() ==  plainText.size());
  
  switch (keyInfo.first) {
  case ObjCryptoAlg::AES128_CTR: {
    assert(  std::holds_alternative<Key128>( keyInfo.second ) );
    Key128 key128 = std::get<Key128>(  keyInfo.second );
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


