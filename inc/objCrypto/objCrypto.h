
namespace "ObjCrypto" {

  typedef enum {
    invalid=0,
    AES128_GCM=1+(1<<3),
    AES128_CTR=1+(2<<3),
    AES256_GCM=2+(1<<3),
    AES256_CTR=2+(2<<3)
  } ObjCryptoAlg;
  
  class ObjCryptor {
    public;
    Cyptor( );

   
    bool addKey( int keyID, char[16] key );
    bool addKey( int keyID, char[32] key );
    bool removeKey( int keyID );

    bool seal(   int keyID,
                 char[13] nonce,
                 char* plainText, int textLen,
                 char* cipherText );
    bool unseal( int keyID,
                 char[13] nonce,
                 char* cipherText, int textLen,
                 char* plainText );
    
    bool seal(   int keyID,
                 char[13] nonce,
                 char* authData, int authDataLen, 
                 char* plainText, int textLen,
                 char* tagData, int tagDataLen,
                 char* cipherText,
                 );
    bool unseal( int keyID,
                 char[13] nonce,
                 char* authData, int authDataLen, 
                 char* cipherText, int textLen,
                 char* tagData, int tagDataLen,
                 char* plainText,
                 );
      
  };

};
