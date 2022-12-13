ARCH ?= x86

all: build-ebpf build run

build-ebpf:
	mkdir -p ebpf/bin
	clang -D__KERNEL__ \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wunused \
		-Wall \
		-Werror \
		-I/lib/modules/$$(uname -r)/build/include \
		-I/lib/modules/$$(uname -r)/build/include/uapi \
		-I/lib/modules/$$(uname -r)/build/include/generated/uapi \
		-I/lib/modules/$$(uname -r)/build/arch/$(ARCH)/include \
		-I/lib/modules/$$(uname -r)/build/arch/$(ARCH)/include/uapi \
		-I/lib/modules/$$(uname -r)/build/arch/$(ARCH)/include/generated \
		-O2 -emit-llvm \
		ebpf/main.c \
		-c -o - | llc -march=bpf -filetype=obj -o ebpf/bin/probe.o

build:
	go build -o bin/main .

run:
	sudo bin/main --kill
