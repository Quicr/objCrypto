// SPDX-FileCopyrightText: Copyright (c) 2022 The ObjCrypto Project Authors
// SPDX-License-Identifier: BSD-2-Clause

#include "crypto.h"
#include "crypto/common.h"
#include <cassert>
#include <CommonCrypto/CommonCryptor.h>

using namespace ObjCrypto;

extern "C" {

// See
// https://opensource.apple.com/source/CommonCrypto/CommonCrypto-60165/include/Private/CommonCryptorSPI.h

CCCryptorStatus CCCryptorGCMOneshotEncrypt(
    CCAlgorithm alg, const void *key, size_t keyLength, /* raw key material */
    const void *iv, size_t ivLength, const void *aData, size_t aDataLength,
    const void *dataIn, size_t dataInLength, void *cipherOut, void *tagOut,
    size_t tagLength)
    __attribute__((__warn_unused_result__))
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

struct scoped_cc_cryptor {
  CCCryptorRef ref;

  ~scoped_cc_cryptor() {
    CCCryptorRelease(ref);
  }
};

Error cc_crypt(CCOperation op, const Key &key, const Nonce &nonce,
                                        const std::vector<uint8_t> &input,
                                        std::vector<uint8_t> &output)
{
  auto cryptor = scoped_cc_cryptor{};
  auto iv = formIV(nonce);

  auto status = CCCryptorCreateWithMode(
          op,           // CCOperation
          kCCModeCTR,           // CCMode
          kCCAlgorithmAES,      // CCAlgorithm
          ccNoPadding,          // CCPadding
          iv.data(),            // const void *iv,
          key_data(key),             // const void *key,
          key_size(key),             // size_t keyLength,
          0,                    // const void *tweak,
          0,                    // size_t tweakLength,
          0,                    // int numRounds,
          kCCModeOptionCTR_BE,  // CCModeOptions
          &cryptor.ref);
  if (status != kCCSuccess) {
    return Error::CryptoLibraryFail;
  }

  size_t moved = 0;
  status = CCCryptorUpdate(
      cryptor.ref,
      input.data(),   // const void *dataIn,
      input.size(),   // size_t dataInLength,
      output.data(),  // void *dataOut,
      output.size(),  // size_t dataOutAvailable,
      &moved              // size_t *dataOutMoved
  );
  if (status != kCCSuccess) {
    return Error::CryptoLibraryFail;
  }

  status = CCCryptorFinal(
      cryptor.ref,
      &output[moved],         // void *dataOut,
      output.size() - moved,  // size_t dataOutAvailable,
      &moved                      // size_t *dataOutMoved
  );

  if (status != kCCSuccess) {
    return Error::CryptoLibraryFail;
  }

  return Error::None;
}


Error ObjCrypto::aes_ctr_encrypt(const Key &key, const Nonce &nonce,
                                        const std::vector<uint8_t> &plainText,
                                        std::vector<uint8_t> &cipherText) {

  return cc_crypt(kCCEncrypt, key, nonce, plainText, cipherText);
}

Error ObjCrypto::aes_ctr_decrypt(const Key &key, const Nonce &nonce,
                                        const std::vector<uint8_t> &cipherText,
                                        std::vector<uint8_t> &plainText) {
  return cc_crypt(kCCDecrypt, key, nonce, cipherText, plainText);
}

Error ObjCrypto::aes_gcm_encrypt(const Key &key, const Nonce &nonce,
                                        const std::vector<uint8_t> &plainText,
                                        const std::vector<uint8_t> &authData,
                                        std::vector<uint8_t> &tag,
                                        std::vector<uint8_t> &cipherText) {
  auto key_data = std::visit([](const auto& k) { return k.data(); }, key);
  auto key_size = std::visit([](const auto& k) { return k.size(); }, key);

  auto status = CCCryptorGCMOneshotEncrypt(
          kCCAlgorithmAES, key_data, key_size, nonce.data(),
          nonce.size(), authData.data(), authData.size(), plainText.data(),
          plainText.size(), cipherText.data(), tag.data(), tag.size());

  if (status != kCCSuccess) {
    return Error::CryptoLibraryFail;
  }

  return Error::None;
}

Error ObjCrypto::aes_gcm_decrypt(const Key &key, const Nonce &nonce,
                                        const std::vector<uint8_t> &cipherText,
                                        const std::vector<uint8_t> &authData,
                                        const std::vector<uint8_t> &tag,
                                        std::vector<uint8_t> &plainText) {
  auto key_data = std::visit([](const auto& k) { return k.data(); }, key);
  auto key_size = std::visit([](const auto& k) { return k.size(); }, key);

  auto status = CCCryptorGCMOneshotDecrypt(
          kCCAlgorithmAES, key_data, key_size, nonce.data(),
          nonce.size(), authData.data(), authData.size(), cipherText.data(),
          cipherText.size(), plainText.data(), tag.data(), tag.size());

  if (status == kCCUnspecifiedError) {
    return Error::DecryptAuthFail;
  }

  if (status != kCCSuccess) {
    return Error::CryptoLibraryFail;
  }

  return Error::None;
}
