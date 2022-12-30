#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <objCrypto/objCrypto.h>
#include <objCrypto/objCryptoVersion.h>

using namespace ObjCrypto;

TEST_CASE("Test key creation and managment") {
    ObjCryptor cryptor;

    Key128 key128 = {0};
    KeyID keyId128 = 5;
    KeyInfo keyInfo128(ObjCryptoAlg::NUL_128_NUL_0, key128);

    Key256 key256 = {0};
    KeyID keyId256 = 9;
    KeyInfo keyInfo256(ObjCryptoAlg::AES_256_GCM_128, key256);

    KeyID keyIdBad = 99;

    CHECK(!cryptor.haveKey(keyIdBad));
      
    CHECK(cryptor.addKey(keyId128, keyInfo128) == ObjCryptoErr::None);

    CHECK(cryptor.addKey(keyId256, keyInfo256) == ObjCryptoErr::None);

    CHECK(cryptor.addKey(keyId128, keyInfo128) == ObjCryptoErr::None);

    CHECK(cryptor.haveKey(keyId256));
    CHECK(cryptor.eraseKey(keyId256) == ObjCryptoErr::None);
    CHECK(!cryptor.haveKey(keyId256));

    CHECK(cryptor.eraseKey(keyId256) == ObjCryptoErr::InvalidKeyID);
}
