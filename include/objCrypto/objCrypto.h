
namespace ObjCrypto {

  typedef enum {
    invalid=0,
    AES128_GCM=1+(1<<3),
    AES128_CTR=1+(2<<3),
    AES256_GCM=2+(1<<3),
    AES256_CTR=2+(2<<3)
  } ObjCryptoAlg;
  
  class ObjCryptor {
  public:
    ObjCryptor( );
    ~ObjCryptor( );
   
    bool addKey( const int keyID, const char key[] , const ObjCryptoAlg alg );
    bool removeKey( int keyID );

    bool seal(   int keyID,
                 char nonce[13],
                 char* plainText, int textLen,
                 char* cipherText );
    bool unseal( int keyID,
                 char nonce[13],
                 char* cipherText, int textLen,
                 char* plainText );
    
    bool seal(   int keyID,
                 char nonce[13],
                 char* authData, int authDataLen, 
                 char* plainText, int textLen,
                 char* tagData, int tagDataLen,
                 char* cipherText );
    bool unseal( int keyID,
                 char nonce[13],
                 char* authData, int authDataLen, 
                 char* cipherText, int textLen,
                 char* tagData, int tagDataLen,
                 char* plainText );
      
  };

};
