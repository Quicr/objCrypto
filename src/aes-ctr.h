#pragma once

#include <objCrypto/objCrypto.h>

namespace ObjCrypto {
  
  ObjCryptoErr aes128_ctr_encrypt( const Key128& key,
                                   const IV& iv,
                                   const std::vector<uint8_t>& plainText,
                                   std::vector<uint8_t>& cipherText);
  
  ObjCryptoErr aes128_ctr_decrypt( 
                                   const Key128& key,
                                   const IV& iv ,
                                   const std::vector<uint8_t>& cipherText,
                                   std::vector<uint8_t>& plainText );
  
};

