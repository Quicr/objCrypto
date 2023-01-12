// SPDX-FileCopyrightText: Copyright (c) 2022 The ObjCrypto Project Authors
// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include <objCrypto/objCrypto.h>

namespace ObjCrypto {

// AES Counter Mode
Error aes_ctr_encrypt(const Key &key, const Nonce &iv,
                      const std::vector<uint8_t> &plainText,
                      std::vector<uint8_t> &cipherText);

Error aes_ctr_decrypt(const Key &key, const Nonce &iv,
                      const std::vector<uint8_t> &cipherText,
                      std::vector<uint8_t> &plainText);

// AES Galois Counter Mode
Error aes_gcm_encrypt(const Key &key, const Nonce &nonce,
                      const std::vector<uint8_t> &plainText,
                      const std::vector<uint8_t> &authData,
                      std::vector<uint8_t> &tag,
                      std::vector<uint8_t> &cipherText);

Error aes_gcm_decrypt(const Key &key, const Nonce &nonce,
                      const std::vector<uint8_t> &cipherText,
                      const std::vector<uint8_t> &authData,
                      const std::vector<uint8_t> &tag,
                      std::vector<uint8_t> &plainText);

};  // namespace ObjCrypto
