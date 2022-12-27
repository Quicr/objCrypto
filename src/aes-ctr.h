#pragma once

#include <objCrypto/objCrypto.h>

namespace ObjCrypto {

ObjCryptoErr aes_ctr_encrypt(const Key &key, const IV &iv, const std::vector<uint8_t> &plainText,
                             std::vector<uint8_t> &cipherText);

ObjCryptoErr aes_ctr_decrypt(const Key &key, const IV &iv, const std::vector<uint8_t> &cipherText,
                             std::vector<uint8_t> &plainText);

}; // namespace ObjCrypto
