// SPDX-FileCopyrightText: Copyright (c) 2022 The ObjCrypto Project Authors
// SPDX-License-Identifier: BSD-2-Clause

#include <cassert>

#if defined(OBJ_CRYPTO_USE_BORINGSSL)
#include <openssl/cipher.h>
#endif

#if defined(__APPLE__)
#include <CommonCrypto/CommonCryptor.h>

extern "C" {

// See
// https://opensource.apple.com/source/CommonCrypto/CommonCrypto-60165/include/Private/CommonCryptorSPI.h

CCCryptorStatus CCCryptorGCMOneshotEncrypt(
    CCAlgorithm alg, const void *key, size_t keyLength, /* raw key material */
    const void *iv, size_t ivLength, const void *aData, size_t aDataLength,
    const void *dataIn, size_t dataInLength, void *cipherOut, void *tagOut,
    size_t tagLength) __attribute__((__warn_unused_result__))
API_AVAILABLE(macos(10.13), ios(11.0));

CCCryptorStatus CCCryptorGCMOneshotDecrypt(CCAlgorithm alg, const void *key,
                                           size_t keyLength, const void *iv,
                                           size_t ivLen, const void *aData,
                                           size_t aDataLen, const void *dataIn,
                                           size_t dataInLength, void *dataOut,
                                           const void *tagIn, size_t tagLength)
    __attribute__((__warn_unused_result__))
    API_AVAILABLE(macos(10.13), ios(11.0));
}

#endif

#include <objCrypto/objCrypto.h>

#include "aes-gcm.h"

using namespace ObjCrypto;

#if defined(__APPLE__) && !defined(OBJ_CRYPTO_USE_BORINGSSL)
Error ObjCrypto::aes_gcm_encrypt(const Key &key, const Nonce &nonce,
                                 const std::vector<uint8_t> &plainText,
                                 const std::vector<uint8_t> &authData,
                                 std::vector<uint8_t> &tag,
                                 std::vector<uint8_t> &cipherText) {
  CCCryptorStatus status = kCCSuccess;

  switch (key.index()) {
    case 0: {
      auto key128 = std::get<Key128>(key);
      status = CCCryptorGCMOneshotEncrypt(
          kCCAlgorithmAES, key128.data(), key128.size(), nonce.data(),
          nonce.size(), authData.data(), authData.size(), plainText.data(),
          plainText.size(), cipherText.data(), tag.data(), tag.size());
      break;
    }

    case 1: {
      auto key256 = std::get<Key256>(key);
      status = CCCryptorGCMOneshotEncrypt(
          kCCAlgorithmAES, key256.data(), key256.size(), nonce.data(),
          nonce.size(), authData.data(), authData.size(), plainText.data(),
          plainText.size(), cipherText.data(), tag.data(), tag.size());
      break;
    }

    default:
      assert(0);
      return Error::UnkownCryptoAlg;
  }

  assert(status != kCCParamError);
  assert(status == kCCSuccess);

  return Error::None;
}
#endif

#if defined(__APPLE__) && !defined(OBJ_CRYPTO_USE_BORINGSSL)
Error ObjCrypto::aes_gcm_decrypt(const Key &key, const Nonce &nonce,
                                 const std::vector<uint8_t> &cipherText,
                                 const std::vector<uint8_t> &authData,
                                 const std::vector<uint8_t> &tag,
                                 std::vector<uint8_t> &plainText) {
  CCCryptorStatus status;

  switch (key.index()) {
    case 0: {
      auto key128 = std::get<Key128>(key);
      status = CCCryptorGCMOneshotDecrypt(
          kCCAlgorithmAES, key128.data(), key128.size(), nonce.data(),
          nonce.size(), authData.data(), authData.size(), cipherText.data(),
          cipherText.size(), plainText.data(), tag.data(), tag.size());
      break;
    }
    case 1: {
      auto key256 = std::get<Key256>(key);
      status = CCCryptorGCMOneshotDecrypt(
          kCCAlgorithmAES, key256.data(), key256.size(), nonce.data(),
          nonce.size(), authData.data(), authData.size(), cipherText.data(),
          cipherText.size(), plainText.data(), tag.data(), tag.size());
      break;
    }
    default: {
      assert(0);
      return Error::UnkownCryptoAlg;
    }
  }

  // std::cout << "CCCrypto decrypt status = " <<  status << std::endl;
  if (status == kCCUnspecifiedError) {
    return Error::DecryptAuthFail;
  }

  assert(status == kCCSuccess);

  return Error::None;
}
#endif

#if defined(OBJ_CRYPTO_USE_BORINGSSL)
Error ObjCrypto::aes_gcm_encrypt(const Key &key, const Nonce &nonce,
                                 const std::vector<uint8_t> &plainText,
                                 const std::vector<uint8_t> &authData,
                                 std::vector<uint8_t> &tag,
                                 std::vector<uint8_t> &cipherText) {
  int moved = 0;
  int cipherTextLen = 0;

  auto ctx = EVP_CIPHER_CTX_new();
  assert(ctx);

  int ret;

  switch (key.index()) {
    case 0: {
      auto key128 = std::get<Key128>(key);

      ret = EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
      assert(ret == 1);

      ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce.size(),
                                NULL);
      assert(ret == 1);

      ret = EVP_EncryptInit_ex(ctx, NULL, NULL, key128.data(), nonce.data());
      assert(ret == 1);
      break;
    }
    case 1: {
      auto key256 = std::get<Key256>(key);

      ret = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
      assert(ret == 1);

      ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce.size(),
                                NULL);
      assert(ret == 1);

      ret = EVP_EncryptInit_ex(ctx, NULL, NULL, key256.data(), nonce.data());
      assert(ret == 1);
      break;
    }
    default: {
      assert(0);
      return Error::UnkownCryptoAlg;
    }
  }

  // do the AAD Data
  ret = EVP_EncryptUpdate(ctx, NULL, &moved, authData.data(),
                          (int)authData.size());
  assert(ret == 1);

  ret = EVP_EncryptUpdate(ctx, cipherText.data(), &moved, plainText.data(),
                          (int)plainText.size());
  assert(ret == 1);
  cipherTextLen += moved;

  ret = EVP_EncryptFinal_ex(ctx, &cipherText[cipherTextLen], &moved);
  assert(ret == 1);
  cipherTextLen += moved;

  assert(cipherTextLen == cipherText.size());

  ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)tag.size(),
                            tag.data());
  assert(ret == 1);

  EVP_CIPHER_CTX_free(ctx);

  return Error::None;
}
#endif

#if defined(OBJ_CRYPTO_USE_BORINGSSL)
Error ObjCrypto::aes_gcm_decrypt(const Key &key, const Nonce &nonce,
                                 const std::vector<uint8_t> &cipherText,
                                 const std::vector<uint8_t> &authData,
                                 const std::vector<uint8_t> &tag,
                                 std::vector<uint8_t> &plainText) {
  int moved = 0;
  int plainTextLen = 0;

  auto ctx = EVP_CIPHER_CTX_new();
  assert(ctx);

  int ret;
  switch (key.index()) {
    case 0: {
      auto key128 = std::get<Key128>(key);

      ret = EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
      assert(ret == 1);

      ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce.size(),
                                NULL);
      assert(ret == 1);

      ret = EVP_DecryptInit_ex(ctx, NULL, NULL, key128.data(), nonce.data());
      assert(ret == 1);

      break;
    }
    case 1: {
      auto key256 = std::get<Key256>(key);

      ret = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
      assert(ret == 1);

      ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce.size(),
                                NULL);
      assert(ret == 1);

      ret = EVP_DecryptInit_ex(ctx, NULL, NULL, key256.data(), nonce.data());
      assert(ret == 1);

      break;
    }
    default: {
      assert(0);
      return Error::UnkownCryptoAlg;
    }
  }

  // do the AAD Data
  ret = EVP_DecryptUpdate(ctx, NULL, &moved, authData.data(),
                          (int)authData.size());  // what is moved here
  assert(ret == 1);

  ret = EVP_DecryptUpdate(ctx, plainText.data(), &moved, cipherText.data(),
                          (int)cipherText.size());
  assert(ret == 1);
  plainTextLen += moved;

  // do tag
  ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag.size(),
                            (void *)tag.data());
  assert(ret == 1);

  ret = EVP_DecryptFinal_ex(ctx, &plainText[plainTextLen], &moved);

  EVP_CIPHER_CTX_free(ctx);

  if (ret == 0) {
    return Error::DecryptAuthFail;
    plainText.clear();
  }

  assert(ret == 1);
  plainTextLen += moved;

  assert(plainTextLen == plainText.size());

  return Error::None;
}
#endif
