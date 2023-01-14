// SPDX-FileCopyrightText: Copyright (c) 2022 The ObjCrypto Project Authors
// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include <objCrypto/objCrypto.h>

namespace ObjCrypto {

Error aes_ctr_encrypt(const Key &key, const IV &iv,
                      const std::vector<uint8_t> &plainText,
                      std::vector<uint8_t> &cipherText);

Error aes_ctr_decrypt(const Key &key, const IV &iv,
                      const std::vector<uint8_t> &cipherText,
                      std::vector<uint8_t> &plainText);

};  // namespace ObjCrypto
