#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <objCrypto/objCrypto.h>
#include <objCrypto/objCryptoVersion.h>

using namespace ObjCrypto;

TEST_CASE("testing that test framework is in place ") {
    CHECK( 1+1 == 2 );
    CHECK( ObjCryptor::version() == ObjCrypto::objCryptoVersion );
}
