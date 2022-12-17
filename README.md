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


Notes:

Solved dupicate shared symboels for openssl by being in shsred lin

Uses apple crypto on apple devices and boringssl otherwise

Forgeries are trivial with AES-CTR mode with no auth 

Question of if apple gcm causes problems with app store

TODO

Need to make sure the quicr names map correctly to nonce and that maps
correctly to IV

