// SPDX-FileCopyrightText: Copyright (c) 2022 The ObjCrypto Project Authors
// SPDX-License-Identifier: BSD-2-Clause

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include <objCrypto/objCrypto.h>
#include <objCrypto/version.h>

using namespace ObjCrypto;

TEST_CASE("Test version info") {
  CHECK( ObjCryptor::version() == ObjCrypto::objCryptoVersion() );
}
