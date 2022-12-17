
#include <cassert>
#include <iostream>


#include <objCrypto/objCrypto.h>

using namespace ObjCrypto;


int main( int argc, char* argv[]) {
  ObjCryptoErr err;
  
  ObjCryptor cryptor;
  KeyID keyId=1;
  
  std::vector<uint8_t> plaintextIn = { 42,0x2,0x3,0x4,0x5};
  std::vector<uint8_t> ciphertext( plaintextIn.size() ) ;
  std::vector<uint8_t>  plaintextOut( plaintextIn.size() ) ;
  Key128 key128 = { 0x9,0x9 };
  KeyInfo keyInfo(  ObjCryptoAlg::AES128_CTR, key128 );
  
  Nonce nonce = { 0xA, 0xB };
  
  assert( sizeof(ciphertext) == sizeof(plaintextIn) );
  assert( sizeof(ciphertext) == sizeof(plaintextOut) );
  
  err = cryptor.addKey( keyId, keyInfo );
  assert( err == ObjCryptoErr::None );
  
  err = cryptor.seal( keyId, nonce, plaintextIn, ciphertext );
  assert( err == ObjCryptoErr::None);
  
  std::cerr << " cipherText[0]=" << (int)ciphertext[0]
            << " cipherText[1]=" << (int)ciphertext[1]
            << std::endl;
  
  err = cryptor.unseal( keyId, nonce, ciphertext, plaintextOut );
  
  
  if ( err != ObjCryptoErr::None ) {
    std::cerr << "Decrypt failed" << std::endl;
  } else {
    std::cerr << "Decrypt plainText[0]=" << (int)plaintextOut[0] << std::endl;
  }
  
  return 0;
}
