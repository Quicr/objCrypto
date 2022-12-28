# objCrypto

This library encrypts objects using AES in GCM or CTR mode. It supports
128 or 256 bit AES keys and authentication tag lengths of 0, 64, or 128
bits.  The zero bit tags use CTR mode and the others use GCM mode.

It is important to note that really bad things happen if the same nonce
is used to to encrypt different things with the same key. The library
does not provide any protection from the this and the application using
it must make sure this never happens. It is also worth noting that
forgeries are often trivial when using the CTR mode and zero bit tags.

It currently supports OSX using the crypto from the the Apple system
library and will build as a universal binary. It support linux using the
crypto from boringssl and can be compiled as a shared library that hides
the internal symbols to avoid conflicts with any other version openssl
in use by the application.

## Random Notes 

Build a xcode project with
``` 
cmake -GXcode .. 
```

Force use of BoringSSL on apple with 
``` 
cmake -DOBJ_CRYPTO_USE_BORINGSSL=True .. 
``` 

Check out info about library when on an apple 
```
lipo -info src/libobjCrypto.dylib 
```

