// SPDX-FileCopyrightText: Copyright (c) 2022 The ObjCrypto Project Authors
// SPDX-License-Identifier: BSD-2-Clause

#include "crypto.h"
#include "crypto/common.h"
#include <openssl/cipher.h>

using namespace ObjCrypto;

using scoped_evp_ctx =
  std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

struct CtrCipher {
  const EVP_CIPHER* operator()(const Key128& /* unused */) {
    return EVP_aes_128_ctr();
  }
  const EVP_CIPHER* operator()(const Key256& /* unused */) {
    return EVP_aes_256_ctr();
  }
};

struct GcmCipher {
  const EVP_CIPHER* operator()(const Key128& /* unused */) {
    return EVP_aes_128_gcm();
  }
  const EVP_CIPHER* operator()(const Key256& /* unused */) {
    return EVP_aes_256_gcm();
  }
};

Error ObjCrypto::aes_ctr_encrypt(const Key &key, const Nonce &nonce,
                                 const std::vector<uint8_t> &plainText,
                                 std::vector<uint8_t> &cipherText) {
  const auto iv = formIV(nonce);
  auto ctx = scoped_evp_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  if (ctx == NULL) {
    return Error::CryptoLibraryFail;
  }

  const auto* evp_alg = std::visit(CtrCipher{}, key);
  auto status = EVP_EncryptInit_ex(ctx.get(), evp_alg, NULL, NULL, NULL);
  if (status != 1) {
    return Error::CryptoLibraryFail;
  }

  status = EVP_EncryptInit_ex(ctx.get(), NULL, NULL, key_data(key), iv.data());
  if (status != 1) {
    return Error::CryptoLibraryFail;
  }

  int moved = 0;
  status = EVP_EncryptUpdate(ctx.get(), (uint8_t *)cipherText.data(), &moved,
                             (const uint8_t *)plainText.data(),
                             (int)plainText.size());
  if (status != 1) {
    return Error::CryptoLibraryFail;
  }

  status =
      EVP_EncryptFinal_ex(ctx.get(), (uint8_t *)&cipherText[moved], &moved);
  if (status != 1) {
    return Error::CryptoLibraryFail;
  }

  return Error::None;
}

Error ObjCrypto::aes_ctr_decrypt(const Key &key, const Nonce &nonce,
                                        const std::vector<uint8_t> &cipherText,
                                        std::vector<uint8_t> &plainText) {
  const auto iv = formIV(nonce);
  auto ctx = scoped_evp_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  if (ctx == NULL) {
    return Error::CryptoLibraryFail;
  }

  const auto* evp_alg = std::visit(CtrCipher{}, key);
  auto status = EVP_DecryptInit_ex(ctx.get(), evp_alg, NULL, NULL, NULL);
  if (status != 1) {
    return Error::CryptoLibraryFail;
  }

  status = EVP_DecryptInit_ex(ctx.get(), NULL, NULL, key_data(key), iv.data());
  if (status != 1) {
    return Error::CryptoLibraryFail;
  }

  int moved = 0;
  status = EVP_DecryptUpdate(ctx.get(), (uint8_t *)plainText.data(), &moved,
                             (const uint8_t *)cipherText.data(),
                             (int)cipherText.size());
  if (status != 1) {
    return Error::CryptoLibraryFail;
  }

  status =
      EVP_DecryptFinal_ex(ctx.get(), (uint8_t *)&plainText[moved], &moved);
  if (status != 1) {
    return Error::CryptoLibraryFail;
  }

  return Error::None;
}

Error ObjCrypto::aes_gcm_encrypt(const Key &key, const Nonce &nonce,
                                        const std::vector<uint8_t> &plainText,
                                        const std::vector<uint8_t> &authData,
                                        std::vector<uint8_t> &tag,
                                        std::vector<uint8_t> &cipherText) {
  auto ctx = scoped_evp_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  if (ctx == NULL) {
    return Error::CryptoLibraryFail;
  }

  const auto* evp_alg = std::visit(GcmCipher{}, key);
  auto status = EVP_EncryptInit_ex(ctx.get(), evp_alg, NULL, NULL, NULL);
  if (status != 1) {
    return Error::CryptoLibraryFail;
  }

  status = EVP_EncryptInit_ex(ctx.get(), NULL, NULL, key_data(key), nonce.data());
  if (status != 1) {
    return Error::CryptoLibraryFail;
  }

  // Add the AAD Data
  int moved = 0;
  status = EVP_EncryptUpdate(ctx.get(), NULL, &moved, authData.data(),
                          (int)authData.size());
  if (status != 1) {
    return Error::CryptoLibraryFail;
  }

  // Encrypt
  status = EVP_EncryptUpdate(ctx.get(), cipherText.data(), &moved, plainText.data(),
                          (int)plainText.size());
  if (status != 1) {
    return Error::CryptoLibraryFail;
  }

  status = EVP_EncryptFinal_ex(ctx.get(), &cipherText[moved], &moved);
  if (status != 1) {
    return Error::CryptoLibraryFail;
  }

  // Read out the tag
  status = EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, (int)tag.size(),
                            tag.data());
  if (status != 1) {
    return Error::CryptoLibraryFail;
  }

  return Error::None;
}

Error ObjCrypto::aes_gcm_decrypt(const Key &key, const Nonce &nonce,
                                        const std::vector<uint8_t> &cipherText,
                                        const std::vector<uint8_t> &authData,
                                        const std::vector<uint8_t> &tag,
                                        std::vector<uint8_t> &plainText) {
  auto ctx = scoped_evp_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  if (ctx == NULL) {
    return Error::CryptoLibraryFail;
  }

  const auto* evp_alg = std::visit(GcmCipher{}, key);
  auto status = EVP_DecryptInit_ex(ctx.get(), evp_alg, NULL, NULL, NULL);
  if (status != 1) {
    return Error::CryptoLibraryFail;
  }

  status = EVP_DecryptInit_ex(ctx.get(), NULL, NULL, key_data(key), nonce.data());
  if (status != 1) {
    return Error::CryptoLibraryFail;
  }


  // Add the AAD Data
  int moved = 0;
  status = EVP_DecryptUpdate(ctx.get(), NULL, &moved, authData.data(),
                          (int)authData.size());  // what is moved here
  if (status != 1) {
    return Error::CryptoLibraryFail;
  }

  // Decrypt
  status = EVP_DecryptUpdate(ctx.get(), plainText.data(), &moved, cipherText.data(),
                          (int)cipherText.size());
  if (status != 1) {
    return Error::CryptoLibraryFail;
  }

  // Add the tag
  status = EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, (int)tag.size(),
                            (void *)tag.data());
  if (status != 1) {
    return Error::CryptoLibraryFail;
  }

  // Authenticate
  status = EVP_DecryptFinal_ex(ctx.get(), &plainText[moved], &moved);
  if (status != 1) {
    return Error::DecryptAuthFail;
    std::fill(std::begin(plainText), std::end(plainText), 0);
  }

  return Error::None;
}

