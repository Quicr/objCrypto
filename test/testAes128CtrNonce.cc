
#include <cassert>
#include <iostream>


#include <objCrypto/objCrypto.h>

using namespace ObjCrypto;

/*
 * Test vectors are from RFC3686 Test Vector #2
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
  
  std::vector<uint8_t> plainTextIn = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                       0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                                       0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                       0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F  };

  std::vector<uint8_t> cipherText( plainTextIn.size() ) ;
  std::vector<uint8_t> plainTextOut( plainTextIn.size() ) ;

  Key128 key128 = {  0x7E, 0x24, 0x06, 0x78, 0x17, 0xFA, 0xE0, 0xD7,
                           0x43, 0xD6, 0xCE, 0x1F, 0x32, 0x53, 0x91, 0x63 };  
  KeyInfo keyInfo(  ObjCryptoAlg::AES_128_CTR_0, key128 );

  Nonce  nonce = { 0x00, 0x6C, 0xB6, 0xDB, 0xC0, 0x54, 0x3B, 0x59,
                            0xDA, 0x48, 0xD9, 0x0B, 0x00};
 
  err = cryptor.addKey( keyId, keyInfo );
  assert( err == ObjCryptoErr::None );
  
  err = cryptor.seal( keyId, nonce, plainTextIn, cipherText );
  assert( err == ObjCryptoErr::None);

  err = cryptor.unseal( keyId, nonce, cipherText, plainTextOut );
  assert( err == ObjCryptoErr::None);

  std::vector<uint8_t> correct = {0x51, 0x04, 0xA1, 0x06, 0x16, 0x8A, 0x72, 0xD9,
                                  0x79, 0x0D, 0x41, 0xEE, 0x8E, 0xDA, 0xD3, 0x88,
                                  0xEB, 0x2E, 0x1E, 0xFC, 0x46, 0xDA, 0x57, 0xC8,
                                  0xFC, 0xE6, 0x30, 0xDF, 0x91, 0x41, 0xBE, 0x28 };
    
  printHex( "plainTextIn " , plainTextIn.data() , plainTextIn.size() );
  printHex( "plainTextOut" , plainTextOut.data() , plainTextOut.size() );
  printHex( "key128" , key128.data() , sizeof(key128) );
  printHex( "nonce" , nonce.data() , sizeof(nonce) );
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
