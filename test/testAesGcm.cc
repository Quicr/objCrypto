/*
 * test vectors from "The Galois/Counter Mode of Operation (GCM)"
 * by David A. McGrew and John Viega
 * https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
 * Test Case 1 fails on apply Crypto lib ( no plain text )
 * Test case 2 failed on boringssl crypt ( no auth data )
 */

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>

#include <cassert>
#include <iostream>

#include <objCrypto/objCrypto.h>

#include "testHelper.h"

using namespace ObjCrypto;

/*
 * Test vectors are from
 * https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
 * Section 5.1 of NIST 800-38A, 2001 Edition
 */

/*
TEST_CASE("test 1 AES128 GCM IV Mode") {
    ObjCryptoErr err;

    ObjCryptor cryptor;
    KeyID keyId = 1;

    std::vector<uint8_t> plainTextIn = {0};
    std::vector<uint8_t> authData = {0};

    std::vector<uint8_t> cipherText(plainTextIn.size());
    std::vector<uint8_t> plainTextOut(plainTextIn.size());

    Key128 key128 = {0};

    KeyInfo keyInfo(ObjCryptoAlg::AES_128_GCM_128, key128);

    IV iv = {0};

    std::vector<uint8_t> tag(128 / 8);
    assert(tag.size() == 128 / 8);

    err = cryptor.addKey(keyId, keyInfo);
    assert(err == ObjCryptoErr::None);

    err = cryptor.seal(keyId, iv, plainTextIn, authData, tag, cipherText);
    assert(err == ObjCryptoErr::None);

    err = cryptor.unseal(keyId, iv, cipherText, authData, tag, plainTextOut);
    assert(err == ObjCryptoErr::None);

    std::vector<uint8_t> correct = {};
    std::vector<uint8_t> correctTag = {0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61,
                                       0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45, 0x5a};

    printHex("plainTextIn  ", plainTextIn.data(), plainTextIn.size());
    printHex(" plainTextOut", plainTextOut.data(), plainTextOut.size());
    printHex("key128", key128.data(), key128.size());
    printHex("iv", iv.data(), iv.size());
    printHex("tag        ", tag.data(), tag.size());
    printHex(" correctTag", correctTag.data(), correctTag.size());
    printHex("cipherText  ", cipherText.data(), cipherText.size());
    printHex(" correctText", correct.data(), correct.size());

    CHECK(correct.size() == cipherText.size());
    for (int i = 0; i < correct.size(); i++) {
      CHECK (correct[i] == cipherText[i]);
    }

    CHECK(correctTag.size() == tag.size());
    for (int i = 0; i < correctTag.size(); i++) {
      CHECK (correctTag[i] == tag[i]);
    }

    CHECK(plainTextIn.size() == plainTextOut.size());
    for (int i = 0; i < plainTextIn.size(); i++) {
      CHECK (plainTextIn[i] == plainTextOut[i]);
    }
}
*/

/*
TEST_CASE("test 2 AES128 GCM IV Mode")  {
    ObjCryptoErr err;

    ObjCryptor cryptor;
    KeyID keyId = 1;

    std::vector<uint8_t> plainTextIn = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    std::vector<uint8_t> authData = {};
    std::vector<uint8_t> correct = {0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
                                    0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78};
    std::vector<uint8_t> correctTag = {0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
                                       0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf};

    std::vector<uint8_t> cipherText(plainTextIn.size());
    std::vector<uint8_t> plainTextOut(plainTextIn.size());

    Key128 key128 = {0};

    KeyInfo keyInfo(ObjCryptoAlg::AES_128_GCM_128, key128);

    IV iv = {0};

    std::vector<uint8_t> tag(128 / 8);
    assert(tag.size() == 128 / 8);

    err = cryptor.addKey(keyId, keyInfo);
    assert(err == ObjCryptoErr::None);

    err = cryptor.seal(keyId, iv, plainTextIn, authData, tag, cipherText);
    assert(err == ObjCryptoErr::None);

    // tag[0]=0; tag[1]=0; // break tag

    err = cryptor.unseal(keyId, iv, cipherText, authData, tag, plainTextOut);
    assert(err != ObjCryptoErr::DecryptAuthFail);
    assert(err == ObjCryptoErr::None);

    printHex("plainTextIn  ", plainTextIn.data(), plainTextIn.size());
    printHex(" plainTextOut", plainTextOut.data(), plainTextOut.size());
    printHex("key128", key128.data(), key128.size());
    printHex("iv", iv.data(), iv.size());
    printHex("tag        ", tag.data(), tag.size());
    printHex(" correctTag", correctTag.data(), correctTag.size());
    printHex("cipherText  ", cipherText.data(), cipherText.size());
    printHex(" correctText", correct.data(), correct.size());

     CHECK(correct.size() == cipherText.size());
    for (int i = 0; i < correct.size(); i++) {
      CHECK (correct[i] == cipherText[i]);
    }

    CHECK(correctTag.size() == tag.size());
    for (int i = 0; i < correctTag.size(); i++) {
      CHECK (correctTag[i] == tag[i]);
    }

    CHECK(plainTextIn.size() == plainTextOut.size());
    for (int i = 0; i < plainTextIn.size(); i++) {
      CHECK (plainTextIn[i] == plainTextOut[i]);
    }
}
*/

TEST_CASE("test 4 AES 128 GCM Mode") {
    ObjCryptoErr err;

    ObjCryptor cryptor;
    KeyID keyId = 1;

    // Test Case 4 from GCM Spec 
    Key128 key128 = {
      0xFE,0xFF,0xE9,0x92,0x86,0x65,0x73,0x1C,0x6D,0x6A,0x8F,0x94,0x67,0x30,0x83,0x08
    };
    Nonce nonce = {
      0xCA,0xFE,0xBA,0xBE,0xFA,0xCE,0xDB,0xAD,0xDE,0xCA,0xF8,0x88
    };

    std::vector<uint8_t> plainTextIn = {
      0xD9,0x31,0x32,0x25,0xF8,0x84,0x06,0xE5,0xA5,0x59,0x09,0xC5,0xAF,0xF5,0x26,0x9A,
      0x86,0xA7,0xA9,0x53,0x15,0x34,0xF7,0xDA,0x2E,0x4C,0x30,0x3D,0x8A,0x31,0x8A,0x72,
      0x1C,0x3C,0x0C,0x95,0x95,0x68,0x09,0x53,0x2F,0xCF,0x0E,0x24,0x49,0xA6,0xB5,0x25,
      0xB1,0x6A,0xED,0xF5,0xAA,0x0D,0xE6,0x57,0xBA,0x63,0x7B,0x39
    };
    std::vector<uint8_t> authData = {
      0xFE,0xED,0xFA,0xCE,0xDE,0xAD,0xBE,0xEF,0xFE,0xED,0xFA,0xCE,0xDE,0xAD,0xBE,0xEF,
      0xAB,0xAD,0xDA,0xD2
    };
    
    std::vector<uint8_t> correct = {
      0x42,0x83,0x1E,0xC2,0x21,0x77,0x74,0x24,0x4B,0x72,0x21,0xB7,0x84,0xD0,0xD4,0x9C,
      0xE3,0xAA,0x21,0x2F,0x2C,0x02,0xA4,0xE0,0x35,0xC1,0x7E,0x23,0x29,0xAC,0xA1,0x2E,
      0x21,0xD5,0x14,0xB2,0x54,0x66,0x93,0x1C,0x7D,0x8F,0x6A,0x5A,0xAC,0x84,0xAA,0x05,
      0x1B,0xA3,0x0B,0x39,0x6A,0x0A,0xAC,0x97,0x3D,0x58,0xE0,0x91
    };
    std::vector<uint8_t> correctTag = {
      0x5B,0xC9,0x4F,0xBC,0x32,0x21,0xA5,0xDB,0x94,0xFA,0xE9,0x5A,0xE7,0x12,0x1A,0x47
    };

    std::vector<uint8_t> cipherText(plainTextIn.size());
    std::vector<uint8_t> plainTextOut(plainTextIn.size());
 
    KeyInfo keyInfo(ObjCryptoAlg::AES_128_GCM_128, key128);

    std::vector<uint8_t> tag(128 / 8);
    assert(tag.size() == 128 / 8);

    err = cryptor.addKey(keyId, keyInfo);
    assert(err == ObjCryptoErr::None);

    err = cryptor.seal(keyId, nonce, plainTextIn, authData, tag, cipherText);
    assert(err == ObjCryptoErr::None);

    SUBCASE("good tag" ) {
      err = cryptor.unseal(keyId, nonce, cipherText, authData, tag, plainTextOut);
      assert(err != ObjCryptoErr::DecryptAuthFail);
      assert(err == ObjCryptoErr::None);
    }
    SUBCASE("bad tag" ) {
      tag[0]++;  // break tag

      err = cryptor.unseal(keyId, nonce, cipherText, authData, tag, plainTextOut);
      assert(err == ObjCryptoErr::DecryptAuthFail);
      return;
    }
    
    printHex("plainTextIn  ", plainTextIn.data(), plainTextIn.size());
    printHex(" plainTextOut", plainTextOut.data(), plainTextOut.size());
    printHex("       key128", key128.data(), key128.size());
    printHex("        nonce", nonce.data(), nonce.size());
    printHex("tag          ", tag.data(), tag.size());
    printHex(" correctTag  ", correctTag.data(), correctTag.size());
    printHex("cipherText   ", cipherText.data(), cipherText.size());
    printHex(" correctText ", correct.data(), correct.size());

    CHECK(correct.size() == cipherText.size());
    for (int i = 0; i < correct.size(); i++) {
        CHECK(correct[i] == cipherText[i]);
    }

    CHECK(correctTag.size() == tag.size());
    for (int i = 0; i < correctTag.size(); i++) {
        CHECK(correctTag[i] == tag[i]);
    }

    CHECK(plainTextIn.size() == plainTextOut.size());
    for (int i = 0; i < plainTextIn.size(); i++) {
        CHECK(plainTextIn[i] == plainTextOut[i]);
    }
}


TEST_CASE("test 16 AES 256 GCM Mode") {
    ObjCryptoErr err;

    ObjCryptor cryptor;
    KeyID keyId = 1;

    // Test Case 16 from GCM Spec 
    Key256 key256 = {
      0xFE,0xFF,0xE9,0x92,0x86,0x65,0x73,0x1C,0x6D,0x6A,0x8F,0x94,0x67,0x30,0x83,0x08,
      0xFE,0xFF,0xE9,0x92,0x86,0x65,0x73,0x1C,0x6D,0x6A,0x8F,0x94,0x67,0x30,0x83,0x08
    };
    Nonce nonce = {
      0xCA,0xFE,0xBA,0xBE,0xFA,0xCE,0xDB,0xAD,0xDE,0xCA,0xF8,0x88
    };

    std::vector<uint8_t> plainTextIn = {
      0xD9,0x31,0x32,0x25,0xF8,0x84,0x06,0xE5,0xA5,0x59,0x09,0xC5,0xAF,0xF5,0x26,0x9A,
      0x86,0xA7,0xA9,0x53,0x15,0x34,0xF7,0xDA,0x2E,0x4C,0x30,0x3D,0x8A,0x31,0x8A,0x72,
      0x1C,0x3C,0x0C,0x95,0x95,0x68,0x09,0x53,0x2F,0xCF,0x0E,0x24,0x49,0xA6,0xB5,0x25,
      0xB1,0x6A,0xED,0xF5,0xAA,0x0D,0xE6,0x57,0xBA,0x63,0x7B,0x39
    };
    std::vector<uint8_t> authData = {
      0xFE,0xED,0xFA,0xCE,0xDE,0xAD,0xBE,0xEF,0xFE,0xED,0xFA,0xCE,0xDE,0xAD,0xBE,0xEF,
      0xAB,0xAD,0xDA,0xD2
    };
    
    std::vector<uint8_t> correct = {
      0x52,0x2D,0xC1,0xF0,0x99,0x56,0x7D,0x07,0xF4,0x7F,0x37,0xA3,0x2A,0x84,0x42,0x7D,
      0x64,0x3A,0x8C,0xDC,0xBF,0xE5,0xC0,0xC9,0x75,0x98,0xA2,0xBD,0x25,0x55,0xD1,0xAA,
      0x8C,0xB0,0x8E,0x48,0x59,0x0D,0xBB,0x3D,0xA7,0xB0,0x8B,0x10,0x56,0x82,0x88,0x38,
      0xC5,0xF6,0x1E,0x63,0x93,0xBA,0x7A,0x0A,0xBC,0xC9,0xF6,0x62
    };
    std::vector<uint8_t> correctTag = {
      0x76,0xFC,0x6E,0xCE,0x0F,0x4E,0x17,0x68,0xCD,0xDF,0x88,0x53,0xBB,0x2D,0x55,0x1B
    };

    std::vector<uint8_t> cipherText(plainTextIn.size());
    std::vector<uint8_t> plainTextOut(plainTextIn.size());
 
    KeyInfo keyInfo(ObjCryptoAlg::AES_256_GCM_128, key256);

    std::vector<uint8_t> tag(128 / 8);
    assert(tag.size() == 128 / 8);

    err = cryptor.addKey(keyId, keyInfo);
    assert(err == ObjCryptoErr::None);

    err = cryptor.seal(keyId, nonce, plainTextIn, authData, tag, cipherText);
    assert(err == ObjCryptoErr::None);

    SUBCASE("good tag" ) {
      err = cryptor.unseal(keyId, nonce, cipherText, authData, tag, plainTextOut);
      assert(err != ObjCryptoErr::DecryptAuthFail);
      assert(err == ObjCryptoErr::None);
    }
    SUBCASE("bad tag" ) {
      tag[tag.size()-1]++;  // break tag

      err = cryptor.unseal(keyId, nonce, cipherText, authData, tag, plainTextOut);
      assert(err == ObjCryptoErr::DecryptAuthFail);
      return;
    }
    
    printHex("plainTextIn  ", plainTextIn.data(), plainTextIn.size());
    printHex(" plainTextOut", plainTextOut.data(), plainTextOut.size());
    printHex("       key256", key256.data(), key256.size());
    printHex("        nonce", nonce.data(), nonce.size());
    printHex("tag          ", tag.data(), tag.size());
    printHex(" correctTag  ", correctTag.data(), correctTag.size());
    printHex("cipherText   ", cipherText.data(), cipherText.size());
    printHex(" correctText ", correct.data(), correct.size());

    CHECK(correct.size() == cipherText.size());
    for (int i = 0; i < correct.size(); i++) {
        CHECK(correct[i] == cipherText[i]);
    }

    CHECK(correctTag.size() == tag.size());
    for (int i = 0; i < correctTag.size(); i++) {
        CHECK(correctTag[i] == tag[i]);
    }

    CHECK(plainTextIn.size() == plainTextOut.size());
    for (int i = 0; i < plainTextIn.size(); i++) {
        CHECK(plainTextIn[i] == plainTextOut[i]);
    }
}
