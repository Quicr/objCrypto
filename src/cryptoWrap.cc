

#include <openssl/cipher.h>

// __declspec(dllimport)

 __attribute__((visibility("default")))  int callTheWrap( int a, int b ) {

    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    if ( !ctx ) { assert(0); }

  return a+b;
}

