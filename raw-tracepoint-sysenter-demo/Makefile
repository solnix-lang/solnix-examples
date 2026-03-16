.PHONY: all build-bpf build run clean

SNX ?= bpf/raw_sysenter.snx
OBJ ?= .snx/build/raw_sysenter.o

all: build

build-bpf:
	solnixc compile $(SNX) $(OBJ)

build: build-bpf
	mkdir -p build
	go build -o build/loader ./cmd/loader

run: build
	sudo ./build/loader -obj $(abspath $(OBJ))

clean:
	rm -rf build .snx

