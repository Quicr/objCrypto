
#include <cassert>
#include <iostream>


#include <objCrypto/objCrypto.h>

using namespace ObjCrypto;


int main( int argc, char* argv[]) {
  bool ret;
  
  ObjCryptor cryptor;
  const int keyId=1;

   char plaintextIn[5] = { 42,0x2,0x3,0x4,0x5};
  unsigned char ciphertext[5];
   char plaintextOut[5];
  unsigned char aad[3] = { 0x5,0x6,0x7 };
  unsigned char key[32] = { 0x9,0x9 };
  unsigned char nonce[13] = { 0xA, 0xB };
  unsigned char tag[32];

  assert( sizeof(ciphertext) == sizeof(plaintextIn) );
  assert( sizeof(ciphertext) == sizeof(plaintextOut) );
  
  cryptor.addKey( keyId, key, sizeof(key)*8, AES128_CTR );

  ret = cryptor.seal( keyId, nonce, (char*)plaintextIn, sizeof( plaintextIn ), (unsigned char*)ciphertext );
  assert( ret );
  
  std::cerr << " cipherText[0]=" << (int)ciphertext[0]
            << " cipherText[1]=" << (int)ciphertext[1]
            << std::endl;
  
  ret = cryptor.unseal( keyId, nonce, (unsigned char*)ciphertext, sizeof( ciphertext ),(char*) plaintextOut );
  
  
  if ( !ret ) {
    std::cerr << "Decrypt failed" << std::endl;
  } else {
    std::cerr << "Decrypt plainText[0]=" << (int)plaintextOut[0] << std::endl;
  }
  

  return 0;
}
