
#include <iostream>

#include <openssl/cipher.h>

void handleErrors(int e) {
    std::cerr << "handleErrors=" << e << std::endl;

    assert(0);
}

int ctr_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad, int aad_len,
                unsigned char *key, unsigned char *iv, int iv_len, unsigned char *ciphertext,
                unsigned char *tag) {
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors(1);

    /* Initialise the encryption operation. */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, NULL, NULL))
        handleErrors(2);

    /*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
     */
    //  if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CTR_SET_IVLEN, iv_len, NULL))
    //    handleErrors();

    /* Initialise key and IV */
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors(3);

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    //   if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
    //  handleErrors(4);

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors(5);
    ciphertext_len = len;

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors(6);
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int ctr_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad, int aad_len,
                unsigned char *tag, unsigned char *key, unsigned char *iv, int iv_len,
                unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors(7);

    /* Initialise the decryption operation. */
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, NULL, NULL))
        handleErrors(8);

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    // if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CTR_SET_IVLEN, iv_len, NULL))
    //    handleErrors();

    /* Initialise key and IV */
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors(9);

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    //  if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
    //    handleErrors(10);

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors(11);
    plaintext_len = len;

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    } else {
        /* Verify failed */
        return -1;
    }
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
        ctr_encrypt(plaintextIn, plaintextIn_len, aad, aad_len, key, iv, iv_len, ciphertext, tag);

    std::cerr << "cipherLen=" << cipherLen << std::endl;
    std::cerr << " cipherText[0]=" << (int)ciphertext[0] << " cipherText[1]=" << (int)ciphertext[1]
              << std::endl;

    unsigned char plaintextOut[1024];
    int plaintextOut_len = 0;

    // tag[0]=0;
    // aad[0]=0;

    plaintextOut_len =
        ctr_decrypt(ciphertext, cipherLen, aad, aad_len, tag, key, iv, iv_len, plaintextOut);

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
