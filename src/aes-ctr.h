#pragma once

#include <objCrypto/objCrypto.h>

namespace ObjCrypto {
  
  ObjCryptoErr aes128_ctr_encrypt(const std::vector<char>& plainText,
                                  const Key128& key,
                                  const IV& iv, 
                                  std::vector<uint8_t>& cipherText);
  
  ObjCryptoErr aes128_ctr_decrypt( const std::vector<uint8_t>& cipherText,
                                   const Key128& key,
                                   const IV& iv ,
                                   std::vector<char>& plainText );
  
};

