#pragma once

#include <objCrypto/objCrypto.h>

namespace ObjCrypto {
  
  ObjCryptoErr aes128_gcm_encrypt( const Key128& key,
                                   const IV& iv,
                                   const std::vector<uint8_t>& plainText,
                                   const std::vector<uint8_t>& authData,
                                   const std::vector<uint8_t>& tagData, 
                                   std::vector<uint8_t>& cipherText );
  
  ObjCryptoErr aes128_gcm_decrypt( const Key128& key,
                                   const IV& iv,
                                   const std::vector<uint8_t>& cipherText,
                                   const std::vector<uint8_t>& authData,
                                   const std::vector<uint8_t>& tagData, 
                                   std::vector<uint8_t>& plainText );
  
};

