
#include <cassert>
#include <iostream>


#include <objCrypto/objCrypto.h>

using namespace ObjCrypto;

/*
 * Test vectors are from 
 * https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
 * Section 5.1 of NIST 800-38A, 2001 Edition 
 */

void printHex( const char* name , void* data, int size ) {
  uint8_t* ptr = (uint8_t*)data;
  
  std::cout << " " << name << ": ";
  for ( int i=0; i< size; i++ ) {
    std::cout << "_" << std::hex << (int)(ptr[i]);
  }
  std::cout << std::endl;
}


int main( int argc, char* argv[]) {
  ObjCryptoErr err;
  
  ObjCryptor cryptor;
  KeyID keyId=1;
  
  std::vector<uint8_t> plainTextIn = { 0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
                                       0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
                                       0xae,0x2d,0x8a,0x57  };

  std::vector<uint8_t> cipherText( plainTextIn.size() ) ;
  std::vector<uint8_t> plainTextOut( plainTextIn.size() ) ;

  Key128 key128 = {    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
                       0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
   
  KeyInfo keyInfo(  ObjCryptoAlg::AES_128_CTR_0, key128 );

  IV iv = {  0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 
             0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff  };
 
    
  err = cryptor.addKey( keyId, keyInfo );
  assert( err == ObjCryptoErr::None );
  
  err = cryptor.seal( keyId, iv, plainTextIn, cipherText );
  assert( err == ObjCryptoErr::None);

  err = cryptor.unseal( keyId, iv, cipherText, plainTextOut );
  assert( err == ObjCryptoErr::None);

  std::vector<uint8_t> correct = { 0x87,0x4d,0x61,0x91,0xb6,0x20,0xe3,0x26,
                                   0x1b,0xef,0x68,0x64,0x99,0x0d,0xb6,0xce,
                                   0x98,0x06,0xf6,0x6b };
    
  printHex( "plainTextIn " , plainTextIn.data() , plainTextIn.size() );
  printHex( "plainTextOut" , plainTextOut.data() , plainTextOut.size() );
  printHex( "key128" , key128.data() , sizeof(key128) );
  printHex( "iv" , iv.data() , sizeof(iv) );
  printHex( " cipherText" , cipherText.data() , cipherText.size() );
  printHex( "correctText" , correct.data() , correct.size() );

  assert( correct.size()  == cipherText.size() );
  for ( int i=0; i< correct.size() ; i++ ) {
    if ( correct[i] != cipherText[i] ) {
      return 1; // fail
    }
  }

  assert( plainTextIn.size()  == plainTextOut.size() );
  for ( int i=0; i< plainTextIn.size() ; i++ ) {
    if ( plainTextIn[i] != plainTextOut[i] ) {
      return 1; // fail
    }
  }
  return 0;
}
