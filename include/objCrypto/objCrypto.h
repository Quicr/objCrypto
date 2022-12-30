#pragma once

#include <array>
#include <cstdint>
#include <map>
#include <utility>
#include <variant>
#include <vector>

#if (defined _WIN32 && !defined __CYGWIN__)
#if defined(BUILDING_OBJCRYPTO)
#define OBJCRYPTO_EXPORT __declspec(dllexport)
#else
#define OBJCRYPTO_EXPORT __declspec(dllimport)
#endif
#else
#define OBJCRYPTO_EXPORT __attribute__((__visibility__("default")))
#endif

namespace ObjCrypto {

enum class ObjCryptoAlg : uint8_t {
    Invalid = 0,
    NUL_128_NUL_0 = 0x10,   // NULL cipher wiith 128 bit key and 0 byte tag
    NUL_128_NUL_128 = 0x12, // NULL cipher with 128 bit key and 128 bit tag
    AES_128_CTR_0 = 0x20,   // AES128 counter mode with no authentication
    AES_128_GCM_64 = 0x21,  // AES128 GCM mode with 64 bit tag
    AES_128_GCM_128 = 0x22, // AES128 GCM mode with 128 bit tag
    AES_256_CTR_0 = 0x30,   // AES128 counter mode with no authentication
    AES_256_GCM_64 = 0x31,  // AES128 GCM mode with 64 bit tag
    AES_256_GCM_128 = 0x32  // AES128 GCM mode with 128 bit tag
};

typedef std::array<uint8_t, 128 / 8> Key128;
typedef std::array<uint8_t, 256 / 8> Key256;
typedef std::variant<Key128, Key256> Key;
typedef std::pair<ObjCryptoAlg, Key> KeyInfo;

typedef uint32_t KeyID;

typedef std::array<uint8_t, 96 / 8> Nonce;
typedef std::array<uint8_t, 128 / 8> IV;

enum class ObjCryptoErr : uint8_t {
    None = 0,
    DecryptAuthFail,
    InvalidKeyID,
    UnkownCryptoAlg, 
    WrongKeySize,
    WrongTagSize,
    WrongOutputDataSize
};

class ObjCryptor {
  private:
    std::map<KeyID, const KeyInfo> keyInfoMap;

    IV formIV(const Nonce &nonce) const;

  public:
    OBJCRYPTO_EXPORT ObjCryptor();

    OBJCRYPTO_EXPORT ~ObjCryptor();

    OBJCRYPTO_EXPORT static float version();

    OBJCRYPTO_EXPORT ObjCryptoErr addKey(const KeyID keyID, const KeyInfo &key);

    OBJCRYPTO_EXPORT ObjCryptoErr removeKey(KeyID keyID);

    OBJCRYPTO_EXPORT bool haveKey(KeyID keyID) const;

    /* TODO remove
    ObjCryptoErr seal(KeyID keyID, const std::variant<Nonce, IV> &nonceOrIV,
                      const std::vector<uint8_t> &plainText,
                      std::vector<uint8_t> &cipherText) const;

    ObjCryptoErr unseal(KeyID keyID, const std::variant<Nonce, IV> &nonceOrIV,
                        const std::vector<uint8_t> &cipherText,
                        std::vector<uint8_t> &plainText) const;
    */

    OBJCRYPTO_EXPORT ObjCryptoErr seal(KeyID keyID, const Nonce &nonce,
                                       const std::vector<uint8_t> &plainText,
                                       const std::vector<uint8_t> &authData,
                                       std::vector<uint8_t> &tag,
                                       std::vector<uint8_t> &cipherText) const;

    OBJCRYPTO_EXPORT ObjCryptoErr unseal(KeyID keyID, const Nonce &nonce,
                                         const std::vector<uint8_t> &cipherText,
                                         const std::vector<uint8_t> &authData,
                                         const std::vector<uint8_t> &tag,
                                         std::vector<uint8_t> &plainText) const;
};

}; // namespace ObjCrypto
