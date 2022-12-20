#include <cassert>
#include <cstring>

#include "aes-ctr.h"
#include "aes-gcm.h"

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


static void formIV( const std::variant< Nonce, IV>& nonceOrIV, IV& iv ){
    if ( std::holds_alternative<IV>( nonceOrIV) ) {
      iv = std::get<IV>( nonceOrIV );
    } else {
      Nonce nonce = std::get<Nonce>( nonceOrIV );
      assert( sizeof( iv ) > sizeof( nonce ) );
      std::memcpy( iv.data(), nonce.data(), sizeof( nonce ) );
      assert( sizeof(iv) == 16 );
      assert( iv.size() == 16 );
      assert( sizeof( nonce ) == 13 );
      iv[13] = 0;
      iv[14] = 0;
      iv[15] = 1; // This 1 is specified in RFC 3686
    }
}


__attribute__((visibility("default")))
ObjCryptoErr ObjCryptor::seal( KeyID keyID,
                               const std::variant< Nonce, IV>& nonceOrIV,
                               const std::vector<uint8_t>& plainText,
                               std::vector<uint8_t>& cipherText  ){
  assert( haveKey( keyID ) );
  const KeyInfo& keyInfo = keyInfoMap.at( keyID );

  assert( plainText.size() == cipherText.size() );
           
  switch (keyInfo.first) {
  case ObjCryptoAlg::AES128_CTR: {
    assert(  std::holds_alternative<Key128>( keyInfo.second ) );
    Key128 key = std::get<Key128>(  keyInfo.second );

    IV iv;
    formIV( nonceOrIV, iv );
    
    assert( sizeof(iv) == sizeof(key) );
    assert( plainText.size() <= ( sizeof(key) * (1<<24) ) );

    aes128_ctr_encrypt( key, iv,  plainText, cipherText);
    
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
                                const std::variant<Nonce,IV>& nonceOrIV,
                                 const std::vector<uint8_t>& cipherText, 
                                 std::vector<uint8_t>& plainText ){
   assert( haveKey( keyID ) );
  const KeyInfo& keyInfo = keyInfoMap.at( keyID );

  assert( cipherText.size() ==  plainText.size());
  
  switch (keyInfo.first) {
  case ObjCryptoAlg::AES128_CTR: {
    assert(  std::holds_alternative<Key128>( keyInfo.second ) );
    Key128 key128 = std::get<Key128>(  keyInfo.second );
    assert( sizeof(key128) == 128/8 );

    IV iv;
    formIV( nonceOrIV, iv );
 
    aes128_ctr_decrypt( key128, iv, cipherText, plainText );
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
ObjCryptoErr ObjCryptor::seal(   KeyID keyID,
                                 const std::variant<Nonce,IV>& nonceOrIV,
                                 const std::vector<uint8_t>& plainText, 
                                 const std::vector<uint8_t>& authData, 
                                 std::vector<uint8_t>& tag, 
                                 std::vector<uint8_t>& cipherText )
{
  assert( haveKey( keyID ) );
  const KeyInfo& keyInfo = keyInfoMap.at( keyID );

  assert( plainText.size() == cipherText.size() );
           
  switch (keyInfo.first) {
  case ObjCryptoAlg::AES128_CTR:
    assert(0);
    break;
    
  case ObjCryptoAlg::AES128_GCM: {
    assert(  std::holds_alternative<Key128>( keyInfo.second ) );
    Key128 key = std::get<Key128>(  keyInfo.second );

    IV iv;
    formIV( nonceOrIV, iv );
    
    assert( sizeof(iv) == sizeof(key) );
    assert( plainText.size() <= ( sizeof(key) * (1<<24) ) );

    aes128_gcm_encrypt( key, iv,  plainText, authData, tag, cipherText);
    
    break;
  }
  
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
                                 const std::variant<Nonce,IV>& nonceOrIV,
                                 const std::vector<uint8_t>& cipherText, 
                                 const std::vector<uint8_t>& authData,
                                 const std::vector<uint8_t>& tag, 
                                 std::vector<uint8_t>& plainText )
{
   assert( haveKey( keyID ) );
  const KeyInfo& keyInfo = keyInfoMap.at( keyID );

  assert( plainText.size() == cipherText.size() );
           

  switch (keyInfo.first) {
  case ObjCryptoAlg::AES128_CTR:
    assert(0);
    break;
    
  case ObjCryptoAlg::AES128_GCM: {
    assert(  std::holds_alternative<Key128>( keyInfo.second ) );
    Key128 key = std::get<Key128>(  keyInfo.second );

    IV iv;
    formIV( nonceOrIV, iv );
    
    assert( sizeof(iv) == sizeof(key) );
    assert( plainText.size() <= ( sizeof(key) * (1<<24) ) );

    return aes128_gcm_decrypt( key, iv, cipherText, authData, tag, plainText);
    
    break;
  }
  
  case ObjCryptoAlg::AES256_GCM:
  case ObjCryptoAlg::AES256_CTR: 
  default:
    assert(0);
    break;
  }
  
  return ObjCryptoErr::None;
}
