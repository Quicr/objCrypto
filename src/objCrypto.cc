// SPDX-FileCopyrightText: Copyright (c) 2022 The ObjCrypto Project Authors
// SPDX-License-Identifier: BSD-2-Clause

#include <algorithm>
#include <cassert>

#define BUILDING_OBJCRYPTO 1

#include <objCrypto/objCrypto.h>
#include <objCrypto/version.h>

#include "aes-ctr.h"
#include "aes-gcm.h"

using namespace ObjCrypto;

OBJCRYPTO_EXPORT ObjCryptor::ObjCryptor() {
  IV iv;
  assert(sizeof(iv) == 128 / 8);
  assert(iv.size() == 128 / 8);

  Nonce nonce;
  assert(sizeof(nonce) == 96 / 8);
  assert(nonce.size() == 96 / 8);
}

OBJCRYPTO_EXPORT ObjCryptor::~ObjCryptor() { keyInfoMap.clear(); }

OBJCRYPTO_EXPORT int16_t ObjCryptor::version() {
  return ObjCrypto::objCryptoVersion();
}

OBJCRYPTO_EXPORT Error ObjCryptor::eraseKey(KeyID keyID) {
  if (!haveKey(keyID)) {
    return Error::InvalidKeyID;
  }

  keyInfoMap.erase(keyID);

  return Error::None;
}

OBJCRYPTO_EXPORT bool ObjCryptor::haveKey(KeyID keyID) const {
  if (keyInfoMap.find(keyID) != keyInfoMap.end()) {
    return true;
  }
  return false;
}

OBJCRYPTO_EXPORT Error ObjCryptor::addKey(const KeyID keyID,
                                          const KeyInfo &keyInfo) {
  switch (keyInfo.first) {
    case ObjCryptoAlg::AES_128_GCM_128:
    case ObjCryptoAlg::AES_128_GCM_64:
    case ObjCryptoAlg::AES_128_CTR_0: {
      if (!std::holds_alternative<Key128>(keyInfo.second)) {
        return Error::WrongKeySize;
      }
      break;
    }

    case ObjCryptoAlg::AES_256_GCM_128:
    case ObjCryptoAlg::AES_256_GCM_64:
    case ObjCryptoAlg::AES_256_CTR_0: {
      if (!std::holds_alternative<Key256>(keyInfo.second)) {
        return Error::WrongKeySize;
      }

      break;
    }

    case ObjCryptoAlg::NUL_128_NUL_0:
    case ObjCryptoAlg::NUL_128_NUL_128: {
      if (!std::holds_alternative<Key128>(keyInfo.second)) {
        return Error::WrongKeySize;
      }
      break;
    }

    default: {
      return Error::UnkownCryptoAlg;
    }
  }

  if (haveKey(keyID)) {
    auto err = eraseKey(keyID);
    assert(err == Error::None);
  }

  keyInfoMap.insert(std::make_pair(keyID, keyInfo));

  return Error::None;
}

IV ObjCryptor::formIV(const Nonce &nonce) const {
  IV iv;
  assert(iv.size() > nonce.size());
  std::copy(std::begin(nonce), std::end(nonce), std::begin(iv));

  assert(iv.size() == 16);
  assert(nonce.size() == 12);
  iv[12] = 0;
  iv[13] = 0;
  iv[14] = 0;
  iv[15] = 1;  // This 1 is specified in RFC 3686

  return iv;
}

OBJCRYPTO_EXPORT Error ObjCryptor::seal(
    KeyID keyID, const Nonce &nonce, const std::vector<uint8_t> &plainText,
    const std::vector<uint8_t> &authData, std::vector<uint8_t> &tag,
    std::vector<uint8_t> &cipherText) const {
  // check have key
  if (!haveKey(keyID)) {
    return Error::InvalidKeyID;
  }
  const auto keyInfo = keyInfoMap.at(keyID);

  // check tag size correct
  switch (keyInfo.first) {
    case ObjCryptoAlg::NUL_128_NUL_0:
    case ObjCryptoAlg::AES_128_CTR_0:
    case ObjCryptoAlg::AES_256_CTR_0: {
      if (tag.size() != 0) {
        return Error::WrongTagSize;
      }
      break;
    }
    case ObjCryptoAlg::AES_128_GCM_64:
    case ObjCryptoAlg::AES_256_GCM_64: {
      if (tag.size() != 64 / 8) {
        return Error::WrongTagSize;
      }
      break;
    }
    case ObjCryptoAlg::AES_128_GCM_128:
    case ObjCryptoAlg::AES_256_GCM_128:
    case ObjCryptoAlg::NUL_128_NUL_128: {
      if (tag.size() != 128 / 8) {
        return Error::WrongTagSize;
      }
      break;
    }
    default: {
      return Error::UnkownCryptoAlg;
    }
  }

  // check output data size correct
  if (cipherText.size() != plainText.size()) {
    return Error::WrongOutputDataSize;
  }

  auto ret = Error::None;

  switch (keyInfo.first) {
    case ObjCryptoAlg::NUL_128_NUL_0: {
      cipherText = plainText;
      break;
    }
    case ObjCryptoAlg::NUL_128_NUL_128: {
      cipherText = plainText;
      tag.clear();
      break;
    }

    case ObjCryptoAlg::AES_128_CTR_0:
    case ObjCryptoAlg::AES_256_CTR_0: {
      IV iv = formIV(nonce);
      const Key &key = keyInfo.second;
      ret = aes_ctr_encrypt(key, iv, plainText, cipherText);
      break;
    }

    case ObjCryptoAlg::AES_128_GCM_64:
    case ObjCryptoAlg::AES_128_GCM_128:
    case ObjCryptoAlg::AES_256_GCM_64:
    case ObjCryptoAlg::AES_256_GCM_128: {
      const Key &key = keyInfo.second;
      ret = aes_gcm_encrypt(key, nonce, plainText, authData, tag, cipherText);
      break;
    }

    default:
      return Error::UnkownCryptoAlg;
  }

  return ret;
}

OBJCRYPTO_EXPORT Error ObjCryptor::unseal(
    KeyID keyID, const Nonce &nonce, const std::vector<uint8_t> &cipherText,
    const std::vector<uint8_t> &authData, const std::vector<uint8_t> &tag,
    std::vector<uint8_t> &plainText) const {
  if (!haveKey(keyID)) {
    return Error::InvalidKeyID;
  }
  const KeyInfo &keyInfo = keyInfoMap.at(keyID);

  if (cipherText.size() != plainText.size()) {
    return Error::WrongOutputDataSize;
  }

  auto ret = Error::None;

  switch (keyInfo.first) {
    case ObjCryptoAlg::NUL_128_NUL_0: {
      plainText = cipherText;
      break;
    }
    case ObjCryptoAlg::NUL_128_NUL_128: {
      plainText = cipherText;
      break;
    }

    case ObjCryptoAlg::AES_128_CTR_0:
    case ObjCryptoAlg::AES_256_CTR_0: {
      IV iv = formIV(nonce);
      Key key = keyInfo.second;
      ret = aes_ctr_decrypt(key, iv, cipherText, plainText);
      break;
    }

    case ObjCryptoAlg::AES_128_GCM_64:
    case ObjCryptoAlg::AES_128_GCM_128:
    case ObjCryptoAlg::AES_256_GCM_64:
    case ObjCryptoAlg::AES_256_GCM_128: {
      const auto key = keyInfo.second;
      ret = aes_gcm_decrypt(key, nonce, cipherText, authData, tag, plainText);
      break;
    }

    default: {
      return Error::UnkownCryptoAlg;
    }
  }

  return ret;
}
