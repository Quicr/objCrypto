
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

void rev(  void* data, const int size ) {
  uint8_t* ptr = (uint8_t*)data;
  uint8_t tmp[size];

  for ( int i=0; i< size; i++ ) {
    tmp[i] = ptr[15-i];
  }
  for ( int i=0; i< size; i++ ) {
    ptr[i] = tmp[i];
  }

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

  Key128 key128 = {   0xabf7158809cf4f3c, 0x2b7e151628aed2a6 };
  rev( key128.data() , sizeof(key128) );
  
  KeyInfo keyInfo(  ObjCryptoAlg::AES128_CTR, key128 );

  IV iv = {  0xf8f9fafbfcfdfeff , 0xf0f1f2f3f4f5f6f7};
  rev( iv.data() , sizeof(iv) );
    
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
