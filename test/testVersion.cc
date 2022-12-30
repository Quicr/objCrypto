#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <objCrypto/objCrypto.h>
#include <objCrypto/objCryptoVersion.h>

using namespace ObjCrypto;

TEST_CASE("Test version info") {
    CHECK(ObjCryptor::version() == ObjCrypto::objCryptoVersion);
}
