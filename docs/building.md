# Building 

The project is a classic cmake project and can be built with:
```
cmake -S . -B build 
cmake --build build
```

Test can be run with:
```
cmake --build build -t test
```

The library can be build as a shared or static library using:
```
cmake -S . -B build BUILD_SHARED_LIBS=False
```

When build as a shared library, all the boringssl symbols are hidden and will not conflict with other version of openssl in use in the same application. 

## Linux 


## Apple 
 
To build an XCode project, run cmake with:
 
Build a xcode project with
``` 
cmake -S . -B build -GXcode 
```


By default, build on apple operating system will use the crypto in the apple System library. 

To force use of BoringSSL on apple , configure CMake with:
``` 
cmake -S . -B build -DOBJ_CRYPTO_USE_BORINGSSL=True
``` 

The ```CMAKE_OSX_ARCHITECTURES``` can be used to controll which architectures are compiled into universal binaries. 

It is possible to see what architectures the library was compiled for  with: 
```
lipo -info src/libobjCrypto.dylib 
```

# Windows 



