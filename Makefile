
all: build

build:
	cmake -B build
	cmake --build build

docker:
	docker build -t obj-crypto-dev .
	docker run -v ${PWD}:/src --rm -it obj-crypto-dev /bin/tcsh -c "cd /src; cmake -B build-linux ; cmake --build build-linux"




