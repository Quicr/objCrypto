// SPDX-FileCopyrightText: Copyright (c) 2022 The ObjCrypto Project Authors
// SPDX-License-Identifier: BSD-2-Clause

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <objCrypto/objCrypto.h>

using namespace ObjCrypto;

TEST_CASE("Test key creation and managment") {
  ObjCryptor cryptor;

  Key128 key128 = {0};
  KeyID keyId128 = 5;
  KeyInfo keyInfo128(ObjCryptoAlg::NUL_128_NUL_0, key128);

  Key256 key256 = {0};
  KeyID keyId256 = 9;
  KeyInfo keyInfo256(ObjCryptoAlg::AES_256_GCM_128, key256);

  KeyID keyIdBad = 99;

  CHECK(keySize(ObjCryptoAlg(ObjCryptoAlg::Invalid)) == -1);
  CHECK(tagSize(ObjCryptoAlg(ObjCryptoAlg::Invalid)) == -1);

  uint8_t badAlg = 0xFF;
  CHECK(keySize(ObjCryptoAlg(badAlg)) == -1);
  CHECK(tagSize(ObjCryptoAlg(badAlg)) == -1);

  CHECK(keySize(ObjCryptoAlg::NUL_128_NUL_0) == 128 / 8);
  CHECK(keySize(ObjCryptoAlg::NUL_128_NUL_64) == 128 / 8);
  CHECK(keySize(ObjCryptoAlg::NUL_128_NUL_128) == 128 / 8);
  CHECK(keySize(ObjCryptoAlg::AES_256_GCM_128) == 256 / 8);

  CHECK(tagSize(ObjCryptoAlg::NUL_128_NUL_0) == 0 / 8);
  CHECK(tagSize(ObjCryptoAlg::NUL_128_NUL_64) == 64 / 8);
  CHECK(tagSize(ObjCryptoAlg::NUL_128_NUL_128) == 128 / 8);
  CHECK(tagSize(ObjCryptoAlg::AES_256_GCM_128) == 128 / 8);

  CHECK(!cryptor.haveKey(keyIdBad));

  CHECK(cryptor.addKey(keyId128, keyInfo128) == Error::None);

  CHECK(cryptor.addKey(keyId256, keyInfo256) == Error::None);

  CHECK(cryptor.addKey(keyId128, keyInfo128) == Error::None);

  CHECK(cryptor.haveKey(keyId256));
  CHECK(cryptor.eraseKey(keyId256) == Error::None);
  CHECK(!cryptor.haveKey(keyId256));

  CHECK(cryptor.eraseKey(keyId256) == Error::InvalidKeyID);
}
