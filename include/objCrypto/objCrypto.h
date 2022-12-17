#pragma once

#include <cstdint>
#include <variant>
#include <array>
#include <map>
#include <utility>
#include <vector>
 

namespace ObjCrypto {

 enum class ObjCryptoAlg:uint8_t {
    Invalid=0,
    AES128_GCM=1+(1<<3),
    AES128_CTR=1+(2<<3),
    AES256_GCM=2+(1<<3),
    AES256_CTR=2+(2<<3)
  };
 
  typedef std::array<uint8_t,16> Key128;
  typedef std::array<uint8_t,32> Key256;
  typedef std::pair<ObjCryptoAlg, std::variant<Key128,Key256> > KeyInfo;

  typedef uint32_t KeyID;
  
  typedef std::array<uint8_t,13> Nonce;
  typedef std::array<uint8_t,16> IV;
    
  enum class ObjCryptoErr:uint8_t {
    None=0
      };
  
  class ObjCryptor {
  private:
    std::map<KeyID,const KeyInfo> keyInfoMap;
  public:
    ObjCryptor( );
    
    ~ObjCryptor( );
   
    ObjCryptoErr addKey( const KeyID keyID,
                 const KeyInfo& key );

    ObjCryptoErr removeKey( KeyID keyID );

    bool haveKey( KeyID keyID );

    ObjCryptoErr seal(   KeyID keyID,
                         const std::variant<Nonce,IV>& nonceOrIV,
                         const std::vector<uint8_t>& plainText,
                         std::vector<uint8_t>& cipherText );
    
    ObjCryptoErr unseal( KeyID keyID,
                         const std::variant<Nonce,IV>& nonceOrIV,
                         const std::vector<uint8_t>& cipherText, 
                         std::vector<uint8_t>& plainText );
    /*
    ObjCryptoErr seal(   KeyID keyID,
                         const Nonce& nonce,
                         uint8_t* authData, int authDataLen, 
                         uint8_t* plainText, int textLen,
                         uint8_t* tagData, int tagDataLen,
                         uint8_t* cipherText );
    
    ObjCryptoErr unseal( KeyID keyID,
                         const Nonce& nonce,
                         uint8_t* authData, int authDataLen, 
                         uint8_t* cipherText, int textLen,
                         uint8_t* tagData, int tagDataLen,
                         uint8_t* plainText );
    */  
  };

};
