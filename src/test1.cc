
#include <iostream>

#include <openssl/cipher.h>

/* 
Again, the decryption operation is much the same as for normal symmetric decryption as described here. The main differences are:

You may optionally pass through an IV length using EVP_CIPHER_CTX_ctrl
AAD data is passed through in zero or more calls to EVP_DecryptUpdate, with the output buffer set to NULL
Prior to the EVP_DecryptFinal_ex call a new call to EVP_CIPHER_CTX_ctrl provides the tag
A non positive return value from EVP_DecryptFinal_ex should be considered as a failure to authenticate ciphertext and/or AAD. It does not necessarily indicate a more serious error.

*/

void handleErrors() {
  assert(0);
}



int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;


    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
        handleErrors();

    /*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
     */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors();

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        handleErrors();

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}



int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
        handleErrors();

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors();

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors();

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
        handleErrors();

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    } else {
        /* Verify failed */
        return -1;
    }
}

int main( int argc, char* argv[] ) {

  unsigned char plaintextIn[5] = { 42,0x2,0x3,0x4,0x5};
  int plaintextIn_len = sizeof(plaintextIn);
 
  unsigned char aad[3] = { 0x5,0x6,0x7 };
  int aad_len = sizeof( aad );
  
  unsigned char key[32] = { 0x9,0x9 };
  
  unsigned char iv[16] = { 0xA, 0xB };
  int iv_len = sizeof(iv );
  
  unsigned char ciphertext[1024];
  unsigned char tag[32];

  int cipherLen = gcm_encrypt(plaintextIn,  plaintextIn_len,
                              aad,  aad_len,
                              key,
                              iv,  iv_len,
                              ciphertext,
                              tag);
    
  
  std::cerr << "cipherLen=" << cipherLen << std::endl;

  unsigned char plaintextOut[1024];
  int plaintextOut_len = 0;

  //tag[0]=0;
  //aad[0]=0;
  
  plaintextOut_len = gcm_decrypt(ciphertext,  cipherLen,
                                 aad,  aad_len,
                                 tag,
                                 key,
                                 iv,iv_len,
                                 plaintextOut);

  if ( plaintextOut_len < 0 ) {
    std::cerr << "Decrypt failed" << std::endl;
  } else {
    std::cerr << "Decrypt plainTextLen=" << plaintextOut_len << std::endl;
    std::cerr << "Decrypt plainText[0]=" << (int)plaintextOut[0] << std::endl;
  }
    
    
  return 0;
}
