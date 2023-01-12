// SPDX-FileCopyrightText: Copyright (c) 2022 The ObjCrypto Project Authors
// SPDX-License-Identifier: BSD-2-Clause

#include <cassert>
#include <algorithm>

#define BUILDING_OBJCRYPTO 1

#include <objCrypto/objCrypto.h>
#include <objCrypto/version.h>

#include "aes-ctr.h"
#include "aes-gcm.h"

using namespace ObjCrypto;

static constexpr size_t KEY_SIZE_INVALID = 0;
static constexpr size_t KEY_SIZE_128 = 128 / 8;
static constexpr size_t KEY_SIZE_256 = 256 / 8;

static constexpr size_t TAG_SIZE_INVALID = 0;
static constexpr size_t TAG_SIZE_0 = 0 / 8;
static constexpr size_t TAG_SIZE_64 = 64 / 8;
static constexpr size_t TAG_SIZE_128 = 128 / 8;

static size_t key_size(const Key& key) {
  return std::visit([](const auto& k) { return k.size(); }, key);
}

static size_t key_size(ObjCryptoAlg alg) {
  switch (alg) {
    case ObjCryptoAlg::Invalid:
      // XXX(RLB): Should return an error or throw
      return KEY_SIZE_INVALID;

    case ObjCryptoAlg::NUL_128_NUL_0:
    case ObjCryptoAlg::NUL_128_NUL_64:
    case ObjCryptoAlg::NUL_128_NUL_128:
    case ObjCryptoAlg::AES_128_CTR_0:
    case ObjCryptoAlg::AES_128_GCM_64:
    case ObjCryptoAlg::AES_128_GCM_128:
      return KEY_SIZE_128;

    case ObjCryptoAlg::AES_256_CTR_0:
    case ObjCryptoAlg::AES_256_GCM_64:
    case ObjCryptoAlg::AES_256_GCM_128:
      return KEY_SIZE_256;
  }
}

static size_t tag_size(ObjCryptoAlg alg) {
  switch (alg) {
    case ObjCryptoAlg::Invalid:
      // XXX(RLB): Should return an error or throw
      return TAG_SIZE_INVALID;

    case ObjCryptoAlg::NUL_128_NUL_0:
    case ObjCryptoAlg::AES_128_CTR_0:
    case ObjCryptoAlg::AES_256_CTR_0:
      return TAG_SIZE_0;

    case ObjCryptoAlg::NUL_128_NUL_64:
    case ObjCryptoAlg::AES_128_GCM_64:
    case ObjCryptoAlg::AES_256_GCM_64:
      return TAG_SIZE_64;

    case ObjCryptoAlg::NUL_128_NUL_128:
    case ObjCryptoAlg::AES_128_GCM_128:
    case ObjCryptoAlg::AES_256_GCM_128:
      return TAG_SIZE_128;
  }
}

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

  const auto& [alg, key] = keyInfo;
  if (key_size(alg) != key_size(key)) {
    return Error::WrongKeySize;
  }

  keyInfoMap.insert_or_assign(keyID, keyInfo);
  return Error::None;
}

OBJCRYPTO_EXPORT Error ObjCryptor::seal(
    KeyID keyID, const Nonce &nonce, const std::vector<uint8_t> &plainText,
    const std::vector<uint8_t> &authData, std::vector<uint8_t> &tag,
    std::vector<uint8_t> &cipherText) const {
  // check have key
  if (!haveKey(keyID)) {
    return Error::InvalidKeyID;
  }
  const auto& [alg, key] = keyInfoMap.at(keyID);

  // check tag size correct
  if (tag.size() != tag_size(alg)) {
    return Error::WrongTagSize;
  }

  // check output data size correct
  if (cipherText.size() != plainText.size()) {
    return Error::WrongOutputDataSize;
  }

  switch (alg) {
    case ObjCryptoAlg::NUL_128_NUL_0:
      cipherText = plainText;
      return Error::None;

    case ObjCryptoAlg::NUL_128_NUL_128:
      cipherText = plainText;
      tag.clear();
      return Error::None;

    case ObjCryptoAlg::AES_128_CTR_0:
    case ObjCryptoAlg::AES_256_CTR_0:
      return aes_ctr_encrypt(key, nonce, plainText, cipherText);

    case ObjCryptoAlg::AES_128_GCM_64:
    case ObjCryptoAlg::AES_128_GCM_128:
    case ObjCryptoAlg::AES_256_GCM_64:
    case ObjCryptoAlg::AES_256_GCM_128:
      return aes_gcm_encrypt(key, nonce, plainText, authData, tag, cipherText);

    default:
      return Error::UnkownCryptoAlg;
  }
}

OBJCRYPTO_EXPORT Error ObjCryptor::unseal(
    KeyID keyID, const Nonce &nonce, const std::vector<uint8_t> &cipherText,
    const std::vector<uint8_t> &authData, const std::vector<uint8_t> &tag,
    std::vector<uint8_t> &plainText) const {
  if (!haveKey(keyID)) {
    return Error::InvalidKeyID;
  }

  const auto& [alg, key] = keyInfoMap.at(keyID);

  if (cipherText.size() != plainText.size()) {
    return Error::WrongOutputDataSize;
  }

  switch (alg) {
    case ObjCryptoAlg::NUL_128_NUL_0:
      plainText = cipherText;
      return Error::None;

    case ObjCryptoAlg::NUL_128_NUL_128:
      plainText = cipherText;
      return Error::None;

    case ObjCryptoAlg::AES_128_CTR_0:
    case ObjCryptoAlg::AES_256_CTR_0:
      return aes_ctr_decrypt(key, nonce, cipherText, plainText);

    case ObjCryptoAlg::AES_128_GCM_64:
    case ObjCryptoAlg::AES_128_GCM_128:
    case ObjCryptoAlg::AES_256_GCM_64:
    case ObjCryptoAlg::AES_256_GCM_128:
      return aes_gcm_decrypt(key, nonce, cipherText, authData, tag, plainText);

    default:
      return Error::UnkownCryptoAlg;
  }
}
