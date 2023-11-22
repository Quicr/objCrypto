// SPDX-FileCopyrightText: Copyright (c) 2022 The ObjCrypto Project Authors
// SPDX-License-Identifier: BSD-2-Clause

#include <array>
#include <span>
#include <vector>

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <objCrypto/objCrypto.h>
#include <objCrypto/version.h>

using namespace ObjCrypto;

int spanSize(const std::span<uint8_t> &a) { return a.size_bytes(); }

TEST_CASE("Test span") {
  uint8_t raw[]{1, 2, 3};
  std::vector<uint8_t> vec{1, 2, 3, 4};
  std::array<uint8_t, 5> arr{1, 2, 3, 4, 5};

  std::span rawSpan{raw};
  CHECK(spanSize(rawSpan) == 3);

  std::span vecSpan{vec};
  CHECK(spanSize(vecSpan) == 4);

  std::span arrSpan{arr};
  CHECK(spanSize(arrSpan) == 5);
}
