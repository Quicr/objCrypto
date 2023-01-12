#include "crypto/common.h"

namespace ObjCrypto {

IV formIV(const Nonce &nonce) {
  IV iv;
  std::copy(std::begin(nonce), std::end(nonce), std::begin(iv));
  std::fill(std::begin(iv) + nonce.size(), std::end(iv), 0);
  iv[15] = 1; // XXX(RLB) Needed to pass tests
  return iv;
}

const uint8_t* key_data(const Key& key) {
  return std::visit([](const auto& k) { return k.data(); }, key);
}

size_t key_size(const Key& key) {
  return std::visit([](const auto& k) { return k.size(); }, key);
}

} // namespace ObjCrypto
