# playCrypto
Messing around with AES 


Build a xcode project with
``` 
cmake -GXcode .. 
```

Force use of BoringSSL on apple with 
``` 
cmake -DOBJ_CRYPTO_USE_BORINGSSL=True .. 
``` 

Check out info about library
```
lipo -info src/libobjCrypto.dylib 
```

