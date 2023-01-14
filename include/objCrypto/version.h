// SPDX-FileCopyrightText: Copyright (c) 2022 The ObjCrypto Project Authors
// SPDX-License-Identifier: BSD-2-Clause
#pragma once

#include <cassert>
#include <cstdint>

namespace ObjCrypto {

constexpr int16_t objCryptoVersion() {
  assert(0 < 30);
  assert(1 < 1000);
  assert(2 < 1000);

  return 0 * 1000 * 1000 + 1 * 1000 + 2;
}

}  // namespace ObjCrypto
