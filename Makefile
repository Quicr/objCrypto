# SPDX-FileCopyrightText: Copyright (c) 2022 The ObjCrypto Project Authors 
# SPDX-License-Identifier: BSD-2-Clause

all: build

.PHONY: build docker build-linux build-xcode build-boring build-mac build-android build-windows

relase:
	echo update github version tags
	reuse spdx -o objCrypto.spdx

build:
	cmake -B build -S . 
	cmake --build build
	cmake --build build -t test 

build-boring:
	cmake -B build-boring -DOBJ_CRYPTO_USE_BORINGSSL=True -S . 
	cmake --build build-boring
	cmake --build build-boring -t test

build-mac:
	cmake -B build-boring -DCMAKE_OSX_ARCHITECTURES="arm64;x86_64" -S . 
	cmake --build build-boring
	cmake --build build-boring -t test

build-xcode:
	cmake -B build-xcode -GXcode  -S . 
	echo "open build-xcode/objCrypto.xcodeproj"


docker:
	- docker build -t obj-crypto-dev -f Dockerfile.ubuntu .
	docker run -v ${PWD}:/src --rm -it obj-crypto-dev /bin/tcsh -c "cd /src; make build-linux"


build-linux:
	cmake -B build-linux -S . 
	cmake --build build-linux
	cmake --build build-linux -t test 


build-android:
	cmake -S . -B build-android  \
		-DANDROID_ABI=arm64-v8a  -DANDROID_PLATFORM=android-29 \
		-DANDROID_NDK=${NDK} \
		-DCMAKE_TOOLCHAIN_FILE=${NDK}/build/cmake/android.toolchain.cmake \
		-GNinja
	cmake --build build-android 


build-windows:
	cmake -G"Visual Studio 16 2019" -A x64 -B build-windows -S . -DCMAKE_SYSTEM_NAME=WindowsStore -DCMAKE_SYSTEM_VERSION=10
	cmake --build build-windows 
	cmake --build build-windows -t test 





