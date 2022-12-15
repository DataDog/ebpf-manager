ARCH ?= x86

all: build-ebpf build run

build-ebpf: build-prog1 build-prog2

build-prog1:
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
		ebpf/prog1.c \
		-c -o - | llc -march=bpf -filetype=obj -o ebpf/bin/probe1.o

build-prog2:
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
		ebpf/prog2.c \
		-c -o - | llc -march=bpf -filetype=obj -o ebpf/bin/probe2.o

build:
	go build -o bin/main .

run:
	sudo bin/main
