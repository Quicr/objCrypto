
#include <cassert>
#include <iostream>


#include <objCrypto/objCrypto.h>

using namespace ObjCrypto;


int main( int argc, char* argv[]) {
  ObjCryptoErr err;
  
  ObjCryptor cryptor;
  KeyID keyId=1;
  
  char plaintextIn[5] = { 42,0x2,0x3,0x4,0x5};
  unsigned char ciphertext[5];
  char plaintextOut[5];
  unsigned char aad[3] = { 0x5,0x6,0x7 };
  Key128 key = { 0x9,0x9 };
  Nonce nonce = { 0xA, 0xB };
  unsigned char tag[32];
  
  assert( sizeof(ciphertext) == sizeof(plaintextIn) );
  assert( sizeof(ciphertext) == sizeof(plaintextOut) );
  
  err = cryptor.addKey( keyId, key, ObjCryptoAlg::AES128_CTR );
  assert( err == ObjCryptoErr::None );
  
  err = cryptor.seal( keyId, nonce, (char*)plaintextIn, sizeof( plaintextIn ), (unsigned char*)ciphertext );
  assert( err == ObjCryptoErr::None);
  
  std::cerr << " cipherText[0]=" << (int)ciphertext[0]
            << " cipherText[1]=" << (int)ciphertext[1]
            << std::endl;
  
  err = cryptor.unseal( keyId, nonce, (unsigned char*)ciphertext, sizeof( ciphertext ),(char*) plaintextOut );
  
  
  if ( err != ObjCryptoErr::None ) {
    std::cerr << "Decrypt failed" << std::endl;
  } else {
    std::cerr << "Decrypt plainText[0]=" << (int)plaintextOut[0] << std::endl;
  }
  

  return 0;
}
