#pragma once

#include <objCrypto/objCrypto.h>

namespace ObjCrypto {

using IV = std::array<uint8_t, 16>;

IV formIV(const Nonce &nonce);

const uint8_t* key_data(const Key& key);
size_t key_size(const Key& key);

} // namespace ObjCrypto
