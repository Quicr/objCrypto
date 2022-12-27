#include <cassert>
#include <cstring>

#include <objCrypto/objCrypto.h>
#include <objCrypto/objCryptoVersion.h>

#include "aes-ctr.h"
#include "aes-gcm.h"

using namespace ObjCrypto;

__attribute__((visibility("default"))) ObjCryptor::ObjCryptor() {
  IV iv;
  assert( sizeof( iv ) == 128/8 );
  assert( iv.size() == 128/8 );

  Nonce nonce;
  assert( sizeof( nonce ) == 96/8 );
  assert( nonce.size() == 96/8 );
}

__attribute__((visibility("default"))) ObjCryptor::~ObjCryptor() {
  keyInfoMap.clear();
}

__attribute__((visibility("default"))) 
float ObjCryptor::version() {
  return ObjCrypto::objCryptoVersion; 
}


__attribute__((visibility("default"))) ObjCryptoErr ObjCryptor::removeKey(KeyID keyID) {
    assert(haveKey(keyID));

    keyInfoMap.erase(keyID);

    return ObjCryptoErr::None;
}

__attribute__((visibility("default"))) bool ObjCryptor::haveKey(KeyID keyID) const {
    if (keyInfoMap.find(keyID) != keyInfoMap.end()) {
        return true;
    }
    return false;
}

__attribute__((visibility("default"))) ObjCryptoErr ObjCryptor::addKey(const KeyID keyID,
                                                                       const KeyInfo &keyInfo) {

    switch (keyInfo.first) {
      
    case ObjCryptoAlg::AES_128_GCM_128:
    case ObjCryptoAlg::AES_128_GCM_64:
    case ObjCryptoAlg::AES_128_CTR_0: {
      assert(std::holds_alternative<Key128>(keyInfo.second));
      break;
    }

    case ObjCryptoAlg::AES_256_GCM_128:
    case ObjCryptoAlg::AES_256_GCM_64:
    case ObjCryptoAlg::AES_256_CTR_0: {
        assert(std::holds_alternative<Key256>(keyInfo.second));
        break;
    }

    case ObjCryptoAlg::NUL_128_NUL_0:
    case ObjCryptoAlg::NUL_128_NUL_128: {
        assert(std::holds_alternative<Key128>(keyInfo.second));
        break;
    }

      
    default:
        assert(0);
        break;
    }

    keyInfoMap.insert(std::make_pair(keyID, keyInfo));
    return ObjCryptoErr::None;
}

IV ObjCryptor::formIV(const Nonce &nonce) const
{
  IV iv;
  assert(sizeof(IV) > sizeof(Nonce));
  std::memcpy(iv.data(), nonce.data(), sizeof(nonce));
  
  assert( iv.size() == 16);
  assert( nonce.size() == 12);
  iv[12] = 0;
  iv[13] = 0;
  iv[14] = 0;
  iv[15] = 1; // This 1 is specified in RFC 3686
  
  return iv;
}

__attribute__((visibility("default"))) ObjCryptoErr
ObjCryptor::seal(KeyID keyID,  const Nonce  &nonce,
                 const std::vector<uint8_t> &plainText, const std::vector<uint8_t> &authData,
                 std::vector<uint8_t> &tag, std::vector<uint8_t> &cipherText) const {
    // check have key
    assert(haveKey(keyID));
    const KeyInfo &keyInfo = keyInfoMap.at(keyID);

    // check tag size correct
    switch (keyInfo.first) {
    case ObjCryptoAlg::NUL_128_NUL_0:
    case ObjCryptoAlg::AES_128_CTR_0:
    case ObjCryptoAlg::AES_256_CTR_0:
      assert(tag.size() == 0);
      break;
    case ObjCryptoAlg::AES_128_GCM_64:
    case ObjCryptoAlg::AES_256_GCM_64:
      assert(tag.size() == 64 / 8);
      break;
    case ObjCryptoAlg::AES_128_GCM_128:
    case ObjCryptoAlg::AES_256_GCM_128:
    case ObjCryptoAlg::NUL_128_NUL_128:
      assert(tag.size() == 128 / 8);
      break;
    default:
      assert(0);
    }

    // check output data size correct
    assert(cipherText.size() == plainText.size());

    ObjCryptoErr ret = ObjCryptoErr::None;

    switch (keyInfo.first) {
    case ObjCryptoAlg::AES_128_CTR_0: {
      IV iv = formIV(nonce);
      const Key128& key = std::get<Key128>(keyInfo.second);
      aes_ctr_encrypt(key, iv, plainText, cipherText);
    }
      break;
      
    case ObjCryptoAlg::AES_256_CTR_0: {
      IV iv =  formIV(nonce );
      const Key256& key = std::get<Key256>(keyInfo.second);
      aes_ctr_encrypt(key, iv, plainText, cipherText);
    }
      break;
      
    case ObjCryptoAlg::AES_128_GCM_64:
    case ObjCryptoAlg::AES_128_GCM_128: {
      const Key128& key = std::get<Key128>(keyInfo.second);
      ret = aes_gcm_encrypt(key, nonce, plainText, authData, tag, cipherText);
    }
      break;
      
    case ObjCryptoAlg::AES_256_GCM_64:
    case ObjCryptoAlg::AES_256_GCM_128: {
      const Key256& key = std::get<Key256>(keyInfo.second);
      ret = aes_gcm_encrypt(key, nonce, plainText, authData, tag, cipherText);
    }
      break;
      
    default:
      assert(0);
      break;
    }

     return ret;
}

__attribute__((visibility("default"))) ObjCryptoErr
ObjCryptor::unseal(KeyID keyID,  const Nonce  &nonce,
                   const std::vector<uint8_t> &cipherText, const std::vector<uint8_t> &authData,
                   const std::vector<uint8_t> &tag, std::vector<uint8_t> &plainText) const {
    assert(haveKey(keyID));
    const KeyInfo &keyInfo = keyInfoMap.at(keyID);

    assert(plainText.size() == cipherText.size());

    ObjCryptoErr ret = ObjCryptoErr::None ; 
    
    switch (keyInfo.first) {
      
    case ObjCryptoAlg::AES_128_CTR_0: {
      Key128 key128 = std::get<Key128>(keyInfo.second);
      IV iv = formIV(nonce);
      ret = aes_ctr_decrypt(key128, iv, cipherText, plainText);
    }
      break;
      
   case ObjCryptoAlg::AES_256_CTR_0: {
      Key256 key256 = std::get<Key256>(keyInfo.second);
      IV iv=formIV(nonce);
      ret = aes_ctr_decrypt(key256, iv, cipherText, plainText);
    }
      break;
      
    case ObjCryptoAlg::AES_128_GCM_64:
    case ObjCryptoAlg::AES_128_GCM_128:{
      Key128 key = std::get<Key128>(keyInfo.second);
      ret = aes_gcm_decrypt(key, nonce, cipherText, authData, tag, plainText);
    }
      break;
      
    case ObjCryptoAlg::AES_256_GCM_64:
    case ObjCryptoAlg::AES_256_GCM_128:{
      Key256 key = std::get<Key256>(keyInfo.second);
      ret = aes_gcm_decrypt(key, nonce, cipherText, authData, tag, plainText);
    }
      break;
      
    default:
      assert(0);
      break;
    }
    
    return ret;
}
