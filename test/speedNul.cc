// SPDX-FileCopyrightText: Copyright (c) 2022 The ObjCrypto Project Authors
// SPDX-License-Identifier: BSD-2-Clause

#include <objCrypto/objCrypto.h>

#include <cassert>
#include <chrono>
#include <iostream>

using namespace ObjCrypto;

int main(/* int argc, char *argv[] */) {
  Error err;

  ObjCryptor cryptor;
  KeyID keyId = 1;

  std::vector<uint8_t> plainTextIn = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40,
                                      0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11,
                                      0x73, 0x93, 0x17, 0x2a};

  std::vector<uint8_t> cipherText(plainTextIn.size());
  std::vector<uint8_t> plainTextOut(plainTextIn.size());

  std::vector<uint8_t> tag;
  std::vector<uint8_t> auth;

  Key128 key128 = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                   0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

  KeyInfo keyInfo(ObjCryptoAlg::NUL_128_NUL_0, key128);

  Nonce nonce = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5,
                 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb};

  err = cryptor.addKey(keyId, keyInfo);
  assert(err == Error::None);

  auto startTime = std::chrono::high_resolution_clock::now();

  const auto loops = 1 * 1000 * 1000;
  for (auto i = 0; i < loops; i++) {
    err = cryptor.seal(keyId, nonce, plainTextIn, auth, tag, cipherText);
    assert(err == Error::None);
  }

  auto endTime = std::chrono::high_resolution_clock::now();
  auto elapsedMS = std::chrono::duration_cast<std::chrono::microseconds>(
      endTime - startTime);
  auto seconds = float(elapsedMS.count()) * 1e-6f;

  const auto bytesProcessed = loops * long(plainTextIn.size());
  std::cout << "mbps of NUL-NUL: "
            << float(bytesProcessed) * 8.0f / seconds / 1.0e6f << std::endl;
  std::cout << "Kbytes of NUL-NUL: " << float(bytesProcessed) / seconds / 1.0e3f
            << std::endl;

  // err = cryptor.unseal( keyId, nonce, cipherText, auth, tag, plainTextOut );
  // assert( err == Error::None);

  return 0;
}
