// SPDX-FileCopyrightText: Copyright (c) 2022 The ObjCrypto Project Authors
// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include <objCrypto/objCrypto.h>

namespace ObjCrypto {

ObjCryptoErr aes_gcm_encrypt(const Key &key, const Nonce &nonce,
                             const std::vector<uint8_t> &plainText,
                             const std::vector<uint8_t> &authData,
                             std::vector<uint8_t> &tag,
                             std::vector<uint8_t> &cipherText);

ObjCryptoErr aes_gcm_decrypt(const Key &key, const Nonce &nonce,
                             const std::vector<uint8_t> &cipherText,
                             const std::vector<uint8_t> &authData,
                             const std::vector<uint8_t> &tag,
                             std::vector<uint8_t> &plainText);

};  // namespace ObjCrypto
