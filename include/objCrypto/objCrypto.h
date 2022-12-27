#pragma once

#include <cstdint>
#include <array>
#include <map>
#include <utility>
#include <vector>

namespace ObjCrypto {

  enum class ObjCryptoAlg : uint8_t {
    Invalid = 0,
      NUL_128_NUL_0, // NULL cipher wiith 128 bit key and 0 byte tak 
      NUL_128_NUL_128, // NULL cipher with 128 bit key and 128 bit tag 
      AES_128_CTR_0,  // AES128 counter mode with no authentication
      AES_128_GCM_64, // AES128 GCM mode with 64 bit tag
      AES_128_GCM_128, // AES128 GCM mode with 128 bit tag
      AES_256_CTR_0,  // AES128 counter mode with no authentication
      AES_256_GCM_64, // AES128 GCM mode with 64 bit tag
      AES_256_GCM_128 // AES128 GCM mode with 128 bit tag
      };

typedef std::array<uint8_t, 128 / 8> Key128;
typedef std::array<uint8_t, 256 / 8> Key256;
typedef std::variant<Key128, Key256> Key;
typedef std::pair<ObjCryptoAlg, Key> KeyInfo;

typedef uint32_t KeyID;

typedef std::array<uint8_t,  96 / 8> Nonce;
typedef std::array<uint8_t, 128 / 8> IV;

enum class ObjCryptoErr : uint8_t {
    None = 0,
    DecryptAuthFail,
    InvalidKey,
    WrongKeySize,
    WrongTagSize,
    WrongOutputDataSize
};

class ObjCryptor {
  private:
    std::map<KeyID, const KeyInfo> keyInfoMap;

    IV formIV(const Nonce &nonce) const;
 
  public:
    ObjCryptor();

    ~ObjCryptor();

    static float version();

    ObjCryptoErr addKey(const KeyID keyID, const KeyInfo &key);

    ObjCryptoErr removeKey(KeyID keyID);

    bool haveKey(KeyID keyID) const;

    /* TODO remove
    ObjCryptoErr seal(KeyID keyID, const std::variant<Nonce, IV> &nonceOrIV,
                      const std::vector<uint8_t> &plainText,
                      std::vector<uint8_t> &cipherText) const;

    ObjCryptoErr unseal(KeyID keyID, const std::variant<Nonce, IV> &nonceOrIV,
                        const std::vector<uint8_t> &cipherText,
                        std::vector<uint8_t> &plainText) const;
    */
    
    ObjCryptoErr seal(KeyID keyID,
                      const Nonce  &nonce,
                      const std::vector<uint8_t> &plainText,
                      const std::vector<uint8_t> &authData,
                      std::vector<uint8_t> &tag,
                      std::vector<uint8_t> &cipherText) const;

    ObjCryptoErr unseal(KeyID keyID,
                        const Nonce  &nonce,
                        const std::vector<uint8_t> &cipherText,
                        const std::vector<uint8_t> &authData,
                        const std::vector<uint8_t> &tag,
                        std::vector<uint8_t> &plainText) const;
};

}; // namespace ObjCrypto
