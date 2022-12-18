
#include <cassert>
#include <iostream>

#include <objCrypto/objCrypto.h>

using namespace ObjCrypto;


int test3() {
  ObjCryptoErr err;
  
  ObjCryptor cryptor;
  KeyID keyId=1;

  // These test vectors are not valid - I just make them TODO 
  std::vector<uint8_t> plainTextIn = { 0x0A, 0x0B, 0x0C, 0x0D,  0x0A, 0x0B, 0x0C, 0x0D,
                                       0x0A, 0x0B, 0x0C, 0x0D,  0x0A, 0x0B, 0x0C, 0x0D};
  std::vector<uint8_t> authData = { 0x01, 0x02, 0x03,0x00  };
 
  std::vector<uint8_t> cipherText( plainTextIn.size() ) ;
  std::vector<uint8_t> plainTextOut( plainTextIn.size() ) ;

  Key128 key128 = {   0 };
   
  KeyInfo keyInfo(  ObjCryptoAlg::AES128_GCM, key128 );

  IV iv = {  0  };
 
  std::vector<uint8_t> tag( 128/8 );
  assert( tag.size() == 128/8 ); 
  
  err = cryptor.addKey( keyId, keyInfo );
  assert( err == ObjCryptoErr::None );

  const long loops = 1*1000*1000;
  for ( int i=0; i<loops; i++ ) {
    err = cryptor.seal( keyId, iv, plainTextIn, authData, tag, cipherText );
    assert( err == ObjCryptoErr::None);
  }
  float seconds = 0.881; // TODO 
  const long bits = loops * plainTextIn.size() * 8;
  std::cout << "mbps of AES128-GCM: " << (float)(bits)/seconds/1.0e6 << std::endl;
  
  // err = cryptor.unseal( keyId, iv, cipherText, authData, tag, plainTextOut );
  //assert( err == ObjCryptoErr::None);
 
  return 0;
}



int main( int argc, char* argv[]) {
  if ( test3() != 0 ) { return 1; }
  return 0;
}
