# VXLAN traffic account

CLANG      ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL    ?= bpftool
CC         ?= gcc

ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
	-Wall -Werror \
	-I/usr/include -I/usr/include/x86_64-linux-gnu

USER_CFLAGS := -g -O2 -Wall -Werror -I/usr/include -Ibuild
USER_LDFLAGS := -lbpf -lelf -lz

# Source files
BPF_SRC    := src/bpf/traffic_account.bpf.c
BPF_OBJ    := build/traffic_account.bpf.o
BPF_SKEL   := build/traffic_account.skel.h
USER_SRCS  := src/user/main.c src/user/ipfix.c
USER_BIN   := build/traffic-account

.PHONY: all clean

all: $(BPF_OBJ) $(USER_BIN)

build:
	@mkdir -p build

$(BPF_OBJ): $(BPF_SRC) src/common.h | build
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

$(BPF_SKEL): $(BPF_OBJ) | build
	$(BPFTOOL) gen skeleton $< > $@

$(USER_BIN): $(USER_SRCS) $(BPF_SKEL) src/common.h src/user/ipfix.h | build
	$(CC) $(USER_CFLAGS) -o $@ $(USER_SRCS) $(USER_LDFLAGS)

clean:
	rm -rf build
