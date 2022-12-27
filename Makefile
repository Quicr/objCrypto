
all: build

.PHONY: build docker build-linux

build:
	cmake -B build
	cmake --build build
	cmake --build build -t test 

build-linux:
	cmake -B build-linux
	cmake --build build-linux
	cmake --build build-linux -t test 

docker:
	- docker build -t obj-crypto-dev -f Dockerfile .
	docker run -v ${PWD}:/src --rm -it obj-crypto-dev /bin/tcsh -c "cd /src; make build-linux"




