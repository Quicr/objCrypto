// SPDX-FileCopyrightText: Copyright (c) 2022 The ObjCrypto Project Authors
// SPDX-License-Identifier: BSD-2-Clause

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
  NUL_128_NUL_0 = 0x10,    // NULL cipher wiith 128 bit key and 0 byte tag
  NUL_128_NUL_128 = 0x12,  // NULL cipher with 128 bit key and 128 bit tag
  AES_128_CTR_0 = 0x20,    // AES128 counter mode with no authentication
  AES_128_GCM_64 = 0x21,   // AES128 GCM mode with 64 bit tag
  AES_128_GCM_128 = 0x22,  // AES128 GCM mode with 128 bit tag
  AES_256_CTR_0 = 0x30,    // AES128 counter mode with no authentication
  AES_256_GCM_64 = 0x31,   // AES128 GCM mode with 64 bit tag
  AES_256_GCM_128 = 0x32   // AES128 GCM mode with 128 bit tag
};

using Key128 = std::array<uint8_t, 128 / 8>;
using Key256 = std::array<uint8_t, 256 / 8>;
using Key = std::variant<Key128, Key256>;
using KeyInfo = std::pair<ObjCryptoAlg, Key>;

using KeyID = uint32_t;

using Nonce = std::array<uint8_t, 96 / 8>;
using IV = std::array<uint8_t, 128 / 8>;

enum class Error : uint8_t {
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
  
  OBJCRYPTO_EXPORT ObjCryptor( ObjCryptor& );

  OBJCRYPTO_EXPORT ~ObjCryptor();

  OBJCRYPTO_EXPORT static int16_t version();

  OBJCRYPTO_EXPORT Error addKey(const KeyID keyID, const KeyInfo &key);

  OBJCRYPTO_EXPORT Error eraseKey(KeyID keyID);

  OBJCRYPTO_EXPORT bool haveKey(KeyID keyID) const;

  OBJCRYPTO_EXPORT Error seal(KeyID keyID, const Nonce &nonce,
                              const std::vector<uint8_t> &plainText,
                              const std::vector<uint8_t> &authData,
                              std::vector<uint8_t> &tag,
                              std::vector<uint8_t> &cipherText) const;

  OBJCRYPTO_EXPORT Error unseal(KeyID keyID, const Nonce &nonce,
                                const std::vector<uint8_t> &cipherText,
                                const std::vector<uint8_t> &authData,
                                const std::vector<uint8_t> &tag,
                                std::vector<uint8_t> &plainText) const;
};

};  // namespace ObjCrypto
