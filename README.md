# objCrypto

This library encrypts objects using AES in GCM or CTR mode. It supports
128 or 256 bit AES keys and authentication tag lengths of 0, 64, or 128
bits.  The zero bit tags use CTR mode and the others use GCM mode.

It currently supports OSX using the crypto from the the Apple system
library and will build as a universal binary. It support linux using the
crypto from boringssl and can be compiled as a shared library that hides
the internal symbols to avoid conflicts with any other version openssl
in use by the application.

More infomation can be found in TODO 

