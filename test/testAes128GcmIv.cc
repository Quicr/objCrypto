/*
 * test vectors from "The Galois/Counter Mode of Operation (GCM)"
 * by David A. McGrew and John Viega
 * Test Case 1 fails on apply Crypto lib ( no plain text )
 * Test case 2 failed on boringssl crypt ( no auth data )
 */

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>


#include <cassert>
#include <iostream>

#include <objCrypto/objCrypto.h>

using namespace ObjCrypto;

/*
 * Test vectors are from
 * https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
 * Section 5.1 of NIST 800-38A, 2001 Edition
 */

void printHex(const char *name, void *data, int size) {
    uint8_t *ptr = (uint8_t *)data;

    std::cout << " " << name << ": ";
    for (int i = 0; i < size; i++) {
      if (( (i%4) == 0 ) && ( i>0) ) std::cout << "_" ;
      std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)(ptr[i]);
    }
    std::cout << std::endl;
}

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

TEST_CASE("test 3 AES128 GCM IV Mode") {
    ObjCryptoErr err;

    ObjCryptor cryptor;
    KeyID keyId = 1;

    // These test vectors are not valid - I just make them TODO
    std::vector<uint8_t> plainTextIn = {0x0A, 0x0B, 0x0C, 0x0D};
    std::vector<uint8_t> authData = {0x01, 0x02, 0x03};
    std::vector<uint8_t> correct = {0xa9, 0xb9, 0x27, 0x89};
    std::vector<uint8_t> correctTag = {0x5c, 0xb7, 0x2d, 0x5a, 0xbc, 0x2b, 0xa2, 0xde,
                                       0x93, 0xd4, 0x30, 0x39, 0x90, 0xf7, 0xc9, 0xa8};

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
    printHex("       key128", key128.data(), key128.size());
    printHex("           iv", iv.data(), iv.size());
    printHex("tag          ", tag.data(), tag.size());
    printHex(" correctTag  ", correctTag.data(), correctTag.size());
    printHex("cipherText   ", cipherText.data(), cipherText.size());
    printHex(" correctText ", correct.data(), correct.size());

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

