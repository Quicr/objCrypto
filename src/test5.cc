
#include <iostream>

#include <CommonCrypto/CommonCryptor.h>

extern "C" {
CCCryptorStatus CCCryptorGCM(CCOperation op,                   /* kCCEncrypt, kCCDecrypt */
                             CCAlgorithm alg, const void *key, /* raw key material */
                             size_t keyLength, const void *iv, size_t ivLen, const void *aData,
                             size_t aDataLen, const void *dataIn, size_t dataInLength,
                             void *dataOut, const void *tag, size_t *tagLength);
}

void handleErrors() { assert(0); }

int gcm_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad, int aad_len,
                unsigned char *key, unsigned char *iv, int iv_len, unsigned char *ciphertext,
                unsigned char *tag) {
    size_t ciphertext_len = 0;

    CCCryptorStatus status =
        CCCrypt(kCCEncrypt,               // CCOperation op,
                kCCAlgorithmAES128,       // CCAlgorithm alg,
                kCCOptionPKCS7Padding,    // CCOptions options,
                key, 128 / 8,             // const void *key, size_t keyLength,
                iv,                       // const void *iv,
                plaintext, plaintext_len, // const void *dataIn, size_t dataInLength,
                ciphertext,               // void *dataOut,
                1024,                     // size_t dataOutAvailable,
                &ciphertext_len           // size_t *dataOutMoved
        );

    assert(status == kCCSuccess);

    return ciphertext_len;
}

int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad, int aad_len,
                unsigned char *tag, unsigned char *key, unsigned char *iv, int iv_len,
                unsigned char *plaintext) {

    size_t plaintext_len = 0;

    /*
      CCOperation 	op,
        CCAlgorithm		alg,
      const void 		*key,
      size_t 			keyLength,
        const void 		*iv,
      size_t 			ivLen,
      const void 		*aData,
      size_t 			aDataLen,
      const void 		*dataIn,
      size_t 			dataInLength,
      void 			*dataOut,
      const void 		*tag,
      size_t 			*tagLength)
    */

    size_t tag_len;

    CCCryptorStatus status =
        CCCryptorGCM(kCCDecrypt,                 // CCOperation op,
                     kCCAlgorithmAES128,         // CCAlgorithm alg,
                     key, 128 / 8,               // const void *key, size_t keyLength,
                     iv,                         // const void *iv,
                     128 / 8,                    //        size_t 			ivLen,
                     ciphertext, ciphertext_len, // const void *dataIn, size_t dataInLength,
                     aad,                        // const void 		*aData,
                     aad_len,                    // size_t 			aDataLen,

                     plaintext, // void *dataOut,
                     tag,       //   const void 		*tag,
                     &tag_len   // size_t 			*tagLength)
        );

    assert(status == kCCSuccess);

    return plaintext_len;
}

int main(int argc, char *argv[]) {

    unsigned char plaintextIn[5] = {42, 0x2, 0x3, 0x4, 0x5};
    int plaintextIn_len = sizeof(plaintextIn);

    unsigned char aad[3] = {0x5, 0x6, 0x7};
    int aad_len = sizeof(aad);

    unsigned char key[32] = {0x9, 0x9};

    unsigned char iv[16] = {0xA, 0xB};
    int iv_len = sizeof(iv);

    unsigned char ciphertext[1024];
    unsigned char tag[32];

    int cipherLen =
        gcm_encrypt(plaintextIn, plaintextIn_len, aad, aad_len, key, iv, iv_len, ciphertext, tag);

    std::cerr << "cipherLen=" << cipherLen << std::endl;

    unsigned char plaintextOut[1024];
    int plaintextOut_len = 0;

    // tag[0]=0;
    // aad[0]=0;

    plaintextOut_len =
        gcm_decrypt(ciphertext, cipherLen, aad, aad_len, tag, key, iv, iv_len, plaintextOut);

    if (plaintextOut_len < 0) {
        std::cerr << "Decrypt failed" << std::endl;
    } else {
        std::cerr << "Decrypt plainTextLen=" << plaintextOut_len << std::endl;
        std::cerr << "Decrypt plainText[0]=" << (int)plaintextOut[0] << std::endl;
    }

    assert(plaintextOut_len == plaintextIn_len);
    assert(plaintextOut[0] == plaintextIn[0]);
    assert(plaintextOut[1] == plaintextIn[1]);
    assert(plaintextOut[2] == plaintextIn[2]);

    return 0;
}
