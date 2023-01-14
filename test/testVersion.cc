// SPDX-FileCopyrightText: Copyright (c) 2022 The ObjCrypto Project Authors
// SPDX-License-Identifier: BSD-2-Clause

#include <iostream>
#include <span>
#include <vector>

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <objCrypto/objCrypto.h>
#include <objCrypto/version.h>

using namespace ObjCrypto;

TEST_CASE("Test version info") {
  CHECK(ObjCryptor::version() == ObjCrypto::objCryptoVersion());
}

// int testSpan( const std::span<uint8_t> &a ) {
//   return a.size_bytes();
// }

TEST_CASE("Test span") {
  uint8_t data[]{1, 2, 3};

  auto a = std::span{data};

  // CHECK( testSpan( std::span( a )  ) = 3 );
}
