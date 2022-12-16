
all: build

.PHONY: build docker

build:
	cmake -B build
	cmake --build build
	cmake --build build -t test 

docker:
	- docker build -t obj-crypto-dev .
	docker run -v ${PWD}:/src --rm -it obj-crypto-dev /bin/tcsh -c "cd /src; cmake -B build-linux ; cmake --build build-linux"




