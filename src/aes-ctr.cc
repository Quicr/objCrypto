// SPDX-FileCopyrightText: Copyright (c) 2022 The ObjCrypto Project Authors
// SPDX-License-Identifier: BSD-2-Clause

#include <cassert>

#if defined(OBJ_CRYPTO_USE_BORINGSSL)
#include <openssl/cipher.h>
#endif

#if defined(__APPLE__)
#include <CommonCrypto/CommonCryptor.h>
#endif

#include <objCrypto/objCrypto.h>

#include "aes-ctr.h"

using namespace ObjCrypto;

using IV = std::array<uint8_t, 16>;

static IV formIV(const Nonce &nonce) {
  IV iv;
  assert( iv.size()  > nonce.size() );
  std::copy( std::begin(nonce), std::end(nonce), std::begin(iv) );

  assert(iv.size() == 16);
  assert(nonce.size() == 12);
  iv[12] = 0;
  iv[13] = 0;
  iv[14] = 0;
  iv[15] = 1;  // This 1 is specified in RFC 3686
               // XXX(RLB) WTF? This isn't IPsec.

  return iv;
}

#if defined(__APPLE__) && !defined(OBJ_CRYPTO_USE_BORINGSSL)
Error ObjCrypto::aes_ctr_encrypt(const Key &key, const Nonce &nonce,
                                        const std::vector<uint8_t> &plainText,
                                        std::vector<uint8_t> &cipherText) {
  CCCryptorRef cryptorRef;

  auto iv = formIV(nonce);

  CCCryptorStatus status;
  switch (key.index()) {
    case 0: {
      Key128 key128 = std::get<Key128>(key);

      status = CCCryptorCreateWithMode(
          kCCEncrypt,       // CCOperation
          kCCModeCTR,       // CCMode
          kCCAlgorithmAES,  // CCAlgorithm
          ccNoPadding,      // CCPadding
          iv.data(),        // const void *iv,
          key128.data(),
          key128.size(),        // const void *key, size_t keyLength
          0,                    // const void *tweak,
          0,                    // size_t tweakLength,
          0,                    // int numRounds,
          kCCModeOptionCTR_BE,  // CCModeOptions
          &cryptorRef);
      break;
    }

    case 1: {
      Key256 key256 = std::get<Key256>(key);

      status = CCCryptorCreateWithMode(
          kCCEncrypt,       // CCOperation
          kCCModeCTR,       // CCMode
          kCCAlgorithmAES,  // CCAlgorithm
          ccNoPadding,      // CCPadding
          iv.data(),        // const void *iv,
          key256.data(),
          key256.size(),        // const void *key, size_t keyLength
          0,                    // const void *tweak,
          0,                    // size_t tweakLength,
          0,                    // int numRounds,
          kCCModeOptionCTR_BE,  // CCModeOptions
          &cryptorRef);
      break;
    }

    default: {
      assert(0);
      return Error::UnkownCryptoAlg;
    }
  }
  assert(status == kCCSuccess);

  size_t cipherTextLen = 0;
  size_t moved = 0;

  status = CCCryptorUpdate(
      cryptorRef, plainText.data(),
      plainText.size(),   // const void *dataIn, size_t dataInLength,
      cipherText.data(),  // void *dataOut,
      cipherText.size(),  // size_t dataOutAvailable,
      &moved              // size_t *dataOutMoved
  );
  assert(status == kCCSuccess);
  cipherTextLen += moved;

  status = CCCryptorFinal(
      cryptorRef,
      &cipherText[cipherTextLen],         // void *dataOut,
      cipherText.size() - cipherTextLen,  // size_t dataOutAvailable,
      &moved                              // size_t *dataOutMoved
  );
  assert(status == kCCSuccess);
  cipherTextLen += moved;

  assert(cipherTextLen == cipherText.size());

  status = CCCryptorRelease(cryptorRef);
  assert(status == kCCSuccess);

  return Error::None;
}
#endif

#if defined(__APPLE__) && !defined(OBJ_CRYPTO_USE_BORINGSSL)
Error ObjCrypto::aes_ctr_decrypt(const Key &key, const Nonce &nonce,
                                        const std::vector<uint8_t> &cipherText,
                                        std::vector<uint8_t> &plainText) {
  CCCryptorRef cryptorRef;

  auto iv = formIV(nonce);

  CCCryptorStatus status;
  switch (key.index()) {
    case 0: {
      Key128 key128 = std::get<Key128>(key);

      status = CCCryptorCreateWithMode(
          kCCDecrypt,       // CCOperation
          kCCModeCTR,       // CCMode
          kCCAlgorithmAES,  // CCAlgorithm
          ccNoPadding,      // CCPadding
          iv.data(),        // const void *iv,
          key128.data(),
          key128.size(),        // const void *key, size_t keyLength
          0,                    // const void *tweak,
          0,                    // size_t tweakLength,
          0,                    // int numRounds,
          kCCModeOptionCTR_BE,  // CCModeOptions
          &cryptorRef);
    } break;

    case 1: {
      Key256 key256 = std::get<Key256>(key);

      status = CCCryptorCreateWithMode(
          kCCDecrypt,       // CCOperation
          kCCModeCTR,       // CCMode
          kCCAlgorithmAES,  // CCAlgorithm
          ccNoPadding,      // CCPadding
          iv.data(),        // const void *iv,
          key256.data(),
          key256.size(),        // const void *key, size_t keyLength
          0,                    // const void *tweak,
          0,                    // size_t tweakLength,
          0,                    // int numRounds,
          kCCModeOptionCTR_BE,  // CCModeOptions
          &cryptorRef);
    } break;

    default: {
      assert(0);
      return Error::UnkownCryptoAlg;
      break;
    }
  }
  assert(status == kCCSuccess);

  size_t plainTextLen = 0;
  size_t moved = 0;
  status = CCCryptorUpdate(
      cryptorRef, cipherText.data(),
      cipherText.size(),  // const void *dataIn, size_t dataInLength,
      plainText.data(),   // void *dataOut,
      plainText.size(),   // size_t dataOutAvailable,
      &moved              // size_t *dataOutMoved
  );
  assert(status == kCCSuccess);
  plainTextLen += moved;

  status = CCCryptorFinal(
      cryptorRef,
      &plainText[plainTextLen],         // void *dataOut,
      plainText.size() - plainTextLen,  // size_t dataOutAvailable,
      &moved                            // size_t *dataOutMoved
  );
  assert(status == kCCSuccess);
  plainTextLen += moved;

  assert(plainTextLen == plainText.size());

  status = CCCryptorRelease(cryptorRef);
  assert(status == kCCSuccess);

  return Error::None;
}
#endif

#if 0
#if defined(OBJ_CRYPTO_USE_BORINGSSL)
Error ObjCrypto::aes_ctr_encrypt(const Key &key, const Nonce &nonce,
                                        const std::vector<uint8_t> &plainText,
                                        std::vector<uint8_t> &cipherText) {
  EVP_CIPHER_CTX *ctx;

  auto iv = formIV(nonce);

  ctx = EVP_CIPHER_CTX_new();
  assert(ctx);

  int status;

  switch (key.index()) {
    case 0: {
      Key128 key128 = std::get<Key128>(key);

      status = EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, NULL, NULL);
      assert(status == 1);

      status =
          EVP_EncryptInit_ex(ctx, NULL, NULL, (const uint8_t *)key128.data(),
                             (const uint8_t *)iv.data());
      assert(status == 1);
    } break;

    case 1: {
      Key256 key256 = std::get<Key256>(key);

      status = EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, NULL, NULL);
      assert(status == 1);

      status =
          EVP_EncryptInit_ex(ctx, NULL, NULL, (const uint8_t *)key256.data(),
                             (const uint8_t *)iv.data());
      assert(status == 1);
    } break;

    default: {
      assert(0);
      return Error::UnkownCryptoAlg;
    }
  }

  int moved = 0;
  int cipherTextLen = 0;
  status = EVP_EncryptUpdate(ctx, (uint8_t *)cipherText.data(), &moved,
                             (const uint8_t *)plainText.data(),
                             (int)plainText.size());
  assert(status == 1);
  cipherTextLen += moved;

  status =
      EVP_EncryptFinal_ex(ctx, (uint8_t *)&cipherText[cipherTextLen], &moved);
  assert(status == 1);
  cipherTextLen += moved;

  assert(cipherTextLen == cipherText.size());

  EVP_CIPHER_CTX_free(ctx);

  return Error::None;
}
#endif

#if defined(OBJ_CRYPTO_USE_BORINGSSL)
Error ObjCrypto::aes_ctr_decrypt(const Key &key, const Nonce &nonce,
                                        const std::vector<uint8_t> &cipherText,
                                        std::vector<uint8_t> &plainText) {
  EVP_CIPHER_CTX *ctx;

  auto iv = formIV(nonce);

  ctx = EVP_CIPHER_CTX_new();
  assert(ctx);

  int status;
  switch (key.index()) {
    case 0: {
      Key128 key128 = std::get<Key128>(key);

      status = EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, NULL, NULL);
      assert(status == 1);

      status =
          EVP_DecryptInit_ex(ctx, NULL, NULL, (const uint8_t *)key128.data(),
                             (const uint8_t *)iv.data());
      assert(status == 1);
    } break;

    case 1: {
      Key256 key256 = std::get<Key256>(key);

      status = EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, NULL, NULL);
      assert(status == 1);

      status =
          EVP_DecryptInit_ex(ctx, NULL, NULL, (const uint8_t *)key256.data(),
                             (const uint8_t *)iv.data());
      assert(status == 1);
    } break;

    default: {
      assert(0);
      return Error::UnkownCryptoAlg;
    }
  }

  int moved = 0;
  int plainTextLen = 0;
  status = EVP_DecryptUpdate(ctx, (uint8_t *)plainText.data(), &moved,
                             (const uint8_t *)cipherText.data(),
                             (int)cipherText.size());
  assert(status == 1);
  plainTextLen += moved;

  status =
      EVP_DecryptFinal_ex(ctx, (uint8_t *)&plainText[plainTextLen], &moved);
  assert(status == 1);
  plainTextLen += moved;

  assert(plainTextLen == plainText.size());

  EVP_CIPHER_CTX_free(ctx);

  return Error::None;
}
#endif
#endif
