#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <cassert>
#include <iostream>

#include <objCrypto/objCrypto.h>

#include "testHelper.h"

using namespace ObjCrypto;

TEST_CASE("test NUL Crypto Mode") {
    ObjCryptoErr err;

    ObjCryptor cryptor;
    KeyID keyId = 1;

    std::vector<uint8_t> plainTextIn = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                                        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};

    std::vector<uint8_t> cipherText(plainTextIn.size());
    std::vector<uint8_t> plainTextOut(plainTextIn.size());
    std::vector<uint8_t> auth;
    std::vector<uint8_t> tag;

    Key128 key128 = {0x7E, 0x24, 0x06, 0x78, 0x17, 0xFA, 0xE0, 0xD7,
                     0x43, 0xD6, 0xCE, 0x1F, 0x32, 0x53, 0x91, 0x63};

    SUBCASE("NUl_128_NUL_0") {
        std::cout << "Run for NUl_128_NUL_0 " << std::endl;

        KeyInfo keyInfo(ObjCryptoAlg::NUL_128_NUL_0, key128);
        err = cryptor.addKey(keyId, keyInfo);
        assert(err == ObjCryptoErr::None);
    }
    SUBCASE("NUl_128_NUL_128") {
        std::cout << "Run for NUl_128_NUL_128 " << std::endl;

        tag.resize(128 / 8);
        KeyInfo keyInfo(ObjCryptoAlg::NUL_128_NUL_128, key128);
        err = cryptor.addKey(keyId, keyInfo);
        assert(err == ObjCryptoErr::None);
    }

    Nonce nonce = {0x00, 0x6C, 0xB6, 0xDB, 0xC0, 0x54, 0x3B, 0x59, 0xDA, 0x48, 0xD9, 0x0B};

    err = cryptor.seal(keyId, nonce, plainTextIn, auth, tag, cipherText);
    assert(err == ObjCryptoErr::None);

    err = cryptor.unseal(keyId, nonce, cipherText, auth, tag, plainTextOut);
    assert(err == ObjCryptoErr::None);

    std::vector<uint8_t> correct = plainTextIn;

    printHex("plainTextIn ", plainTextIn.data(), plainTextIn.size());
    printHex("plainTextOut", plainTextOut.data(), plainTextOut.size());
    printHex("key128", key128.data(), sizeof(key128));
    printHex("nonce", nonce.data(), sizeof(nonce));
    printHex(" cipherText", cipherText.data(), cipherText.size());
    printHex("correctText", correct.data(), correct.size());

    CHECK(correct.size() == cipherText.size());
    for (int i = 0; i < correct.size(); i++) {
        CHECK(correct[i] == cipherText[i]);
    }

    CHECK(plainTextIn.size() == plainTextOut.size());
    for (int i = 0; i < plainTextIn.size(); i++) {
        CHECK(plainTextIn[i] == plainTextOut[i]);
    }
}
