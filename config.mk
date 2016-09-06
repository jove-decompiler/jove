# this just obtains the directory this Makefile resides in
ROOT_DIR := $(shell cd $(dir $(word $(words $(MAKEFILE_LIST)),$(MAKEFILE_LIST)));pwd)

#qemutcg_archs  := x86_64 i386 arm aarch64 mipsel
qemutcg_archs  := aarch64
qemu_dir       := /home/aeden/Hacking/qemu-build
qemu_src_dir   := /home/aeden/Hacking/qemu
llvm_dir       := /usr/local
boost_dir      := /usr
opam_libs_dir  := ~/.opam/system/lib
ocaml_dir      := /usr/lib/ocaml

build_dir      := $(ROOT_DIR)/build
include_dir    := $(ROOT_DIR)/include
qemu_build_dir := $(build_dir)/qemu
