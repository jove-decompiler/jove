# this just obtains the directory this Makefile resides in
ROOT_DIR := $(shell cd $(dir $(word $(words $(MAKEFILE_LIST)),$(MAKEFILE_LIST)));pwd)

#qemutcg_archs += arm
qemutcg_archs += x86_64
#qemutcg_archs += i386
#qemutcg_archs += mipsel
qemutcg_archs += aarch64

ifndef QEMU_BUILD_DIR
$(error QEMU_BUILD_DIR is not set)
endif

ifndef QEMU_SRC_DIR
$(error QEMU_SRC_DIR is not set)
endif

qemu_dir       := /home/aeden/qemu-build
llvm_dir       := /usr

build_dir      := $(ROOT_DIR)/bin
include_dir    := $(ROOT_DIR)/include
qemu_build_dir := $(build_dir)/qemu
