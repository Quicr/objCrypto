
all: build

.PHONY: build docker build-linux build-xcode build-boring-arm64 build-boring-x86

build:
	cmake -B build
	cmake --build build
	cmake --build build -t test 


build-xcode:
	cmake -B build-xcode -GXcode
	echo "open build-xcode/objCrypto.xcodeproj"


docker:
	- docker build -t obj-crypto-dev -f Dockerfile .
	docker run -v ${PWD}:/src --rm -it obj-crypto-dev /bin/tcsh -c "cd /src; make build-linux"


build-boring-arm64:
	cmake -B build-boring-arm64 -DOBJ_CRYPTO_USE_BORINGSSL=True -DCMAKE_OSX_ARCHITECTURES=arm64
	cmake --build build-boring-arm64
	cmake --build build-boring-arm64 -t test 


build-boring-x86:
	cmake -B build-boring-x86 -DOBJ_CRYPTO_USE_BORINGSSL=True -DCMAKE_OSX_ARCHITECTURES=x86_64
	cmake --build build-boring-x86
	cmake --build build-boring-x86 -t test


build-linux:
	cmake -B build-linux
	cmake --build build-linux
	cmake --build build-linux -t test 




