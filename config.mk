# this just obtains the directory this Makefile resides in
ROOT_DIR := $(shell cd $(dir $(word $(words $(MAKEFILE_LIST)),$(MAKEFILE_LIST)));pwd)

#qemutcg_archs += arm
qemutcg_archs += x86_64
#qemutcg_archs += i386
#qemutcg_archs += mipsel
qemutcg_archs += aarch64

qemu_dir       := /home/aeden/qemu-build
qemu_src_dir   := /home/aeden/qemu
llvm_dir       := /usr
boost_dir      := /usr
opam_libs_dir  := ~/.opam/system/lib
ocaml_dir      := /usr/lib/ocaml

build_dir      := $(ROOT_DIR)/bin
include_dir    := $(ROOT_DIR)/include
qemu_build_dir := $(build_dir)/qemu
