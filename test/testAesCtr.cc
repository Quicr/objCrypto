#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <cassert>
#include <iostream>

#include <objCrypto/objCrypto.h>

#include "testHelper.h"

using namespace ObjCrypto;



TEST_CASE("test AES 128 Ctr Mode") {
    ObjCryptoErr err;

    ObjCryptor cryptor;
    KeyID keyId = 1;

    /*
     * Test vector from RFC3686 Test Vector #2
     *
     * Test Vector #2: Encrypting 32 octets using AES-CTR with 128-bit key
     *  AES Key          : 7E 24 06 78 17 FA E0 D7 43 D6 CE 1F 32 53 91 63
     *  AES-CTR IV       : C0 54 3B 59 DA 48 D9 0B
     *  Nonce            : 00 6C B6 DB
     *  Plaintext        : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
     *                   : 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
     *  Ciphertext       : 51 04 A1 06 16 8A 72 D9 79 0D 41 EE 8E DA D3 88
     *                   : EB 2E 1E FC 46 DA 57 C8 FC E6 30 DF 91 41 BE 28
     */
    std::vector<uint8_t> plainTextIn = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                                        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F};

    Key128 key128 = {0x7E, 0x24, 0x06, 0x78, 0x17, 0xFA, 0xE0, 0xD7,
                     0x43, 0xD6, 0xCE, 0x1F, 0x32, 0x53, 0x91, 0x63};
    KeyInfo keyInfo(ObjCryptoAlg::AES_128_CTR_0, key128);
    Nonce nonce = {0x00, 0x6C, 0xB6, 0xDB, 0xC0, 0x54, 0x3B, 0x59, 0xDA, 0x48, 0xD9, 0x0B};
    std::vector<uint8_t> correct = {0x51, 0x04, 0xA1, 0x06, 0x16, 0x8A, 0x72, 0xD9,
                                    0x79, 0x0D, 0x41, 0xEE, 0x8E, 0xDA, 0xD3, 0x88,
                                    0xEB, 0x2E, 0x1E, 0xFC, 0x46, 0xDA, 0x57, 0xC8,
                                    0xFC, 0xE6, 0x30, 0xDF, 0x91, 0x41, 0xBE, 0x28};

    std::vector<uint8_t> cipherText(plainTextIn.size());
    std::vector<uint8_t> plainTextOut(plainTextIn.size());
    std::vector<uint8_t> auth;
    std::vector<uint8_t> tag;

    err = cryptor.addKey(keyId, keyInfo);
    assert(err == ObjCryptoErr::None);

    err = cryptor.seal(keyId, nonce, plainTextIn, auth, tag, cipherText);
    assert(err == ObjCryptoErr::None);

    err = cryptor.unseal(keyId, nonce, cipherText, auth, tag, plainTextOut);
    assert(err == ObjCryptoErr::None);

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


TEST_CASE("test AES 256 Ctr Mode") {
    ObjCryptoErr err;

    ObjCryptor cryptor;
    KeyID keyId = 1;

    /*
     * Test vector from RFC3686 Test Vector #8
     * 
     *   Test Vector #8: Encrypting 32 octets using AES-CTR with 256-bit key
     *   AES Key          : F6 D6 6D 6B D5 2D 59 BB 07 96 36 58 79 EF F8 86
     *                    : C6 6D D5 1A 5B 6A 99 74 4B 50 59 0C 87 A2 38 84
     *   AES-CTR IV       : C1 58 5E F1 5A 43 D8 75
     *   Nonce            : 00 FA AC 24
     *   Plaintext        : 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
     *                    : 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
     *   Ciphertext       : F0 5E 23 1B 38 94 61 2C 49 EE 00 0B 80 4E B2 A9
     *                    : B8 30 6B 50 8F 83 9D 6A 55 30 83 1D 93 44 AF 1C
     */
    
    std::vector<uint8_t> plainTextIn = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };

    Key256 key256 = {
      0xF6, 0xD6, 0x6D, 0x6B, 0xD5, 0x2D, 0x59, 0xBB,
      0x07, 0x96, 0x36, 0x58, 0x79, 0xEF, 0xF8, 0x86,
      0xC6, 0x6D, 0xD5, 0x1A, 0x5B, 0x6A, 0x99, 0x74,
      0x4B, 0x50, 0x59, 0x0C, 0x87, 0xA2, 0x38, 0x84 };
    
    KeyInfo keyInfo(ObjCryptoAlg::AES_256_CTR_0, key256);
    
    Nonce nonce = {
      0x00, 0xFA, 0xAC, 0x24, 0xC1, 0x58, 0x5E, 0xF1,
      0x5A, 0x43, 0xD8, 0x75  };
    
    std::vector<uint8_t> correct = {
      0xF0, 0x5E, 0x23, 0x1B, 0x38, 0x94, 0x61, 0x2C,
      0x49, 0xEE, 0x00, 0x0B, 0x80, 0x4E, 0xB2, 0xA9,
      0xB8, 0x30, 0x6B, 0x50, 0x8F, 0x83, 0x9D, 0x6A,
      0x55, 0x30, 0x83, 0x1D, 0x93, 0x44, 0xAF, 0x1C };

    std::vector<uint8_t> cipherText(plainTextIn.size());
    std::vector<uint8_t> plainTextOut(plainTextIn.size());
    std::vector<uint8_t> auth;
    std::vector<uint8_t> tag;

    err = cryptor.addKey(keyId, keyInfo);
    assert(err == ObjCryptoErr::None);

    err = cryptor.seal(keyId, nonce, plainTextIn, auth, tag, cipherText);
    assert(err == ObjCryptoErr::None);

    err = cryptor.unseal(keyId, nonce, cipherText, auth, tag, plainTextOut);
    assert(err == ObjCryptoErr::None);

    printHex("plainTextIn ", plainTextIn.data(), plainTextIn.size());
    printHex("plainTextOut", plainTextOut.data(), plainTextOut.size());
    printHex("key256", key256.data(), sizeof(key256));
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
