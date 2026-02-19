# nft-traffic-account - VXLAN Traffic Accounting

CLANG      ?= clang
LLVM_STRIP ?= llvm-strip
CC         ?= gcc

ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
	-Wall -Werror \
	-I/usr/include -I/usr/include/x86_64-linux-gnu

USER_CFLAGS := -g -O2 -Wall -Werror -I/usr/include
USER_LDFLAGS := -lbpf -lelf -lz

# Source files
BPF_SRC    := src/bpf/traffic_account.bpf.c
BPF_OBJ    := build/traffic_account.bpf.o
USER_SRCS  := src/user/main.c src/user/ipfix.c
USER_BIN   := build/traffic-account

.PHONY: all clean

all: $(BPF_OBJ) $(USER_BIN)

build:
	@mkdir -p build

$(BPF_OBJ): $(BPF_SRC) src/common.h | build
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

$(USER_BIN): $(USER_SRCS) src/common.h src/user/ipfix.h | build
	$(CC) $(USER_CFLAGS) -o $@ $(USER_SRCS) $(USER_LDFLAGS)

clean:
	rm -rf build
