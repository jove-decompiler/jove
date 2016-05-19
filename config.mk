# this just obtains the directory this Makefile resides in
ROOT_DIR := $(shell cd $(dir $(word $(words $(MAKEFILE_LIST)),$(MAKEFILE_LIST)));pwd)

#qemutcg_archs  := x86_64 i386 arm aarch64 mipsel
qemutcg_archs  := x86_64 aarch64
qemu_dir       := /home/aeden/Hacking/qemu-2.6.0-build
qemu_src_dir   := /home/aeden/Hacking/qemu-2.6.0
llvm_dir       := /home/aeden/Hacking/llvm-3.8.0-install
llvm_flto_dir  := /home/aeden/Software/llvm-3.8.0-install
boost_dir      := /home/aeden/Hacking/boost-1.60.0-install
opam_libs_dir  := ~/.opam/system/lib
ocaml_dir      := /usr/lib/ocaml

build_dir      := $(ROOT_DIR)/build
include_dir    := $(ROOT_DIR)/include
qemu_build_dir := $(build_dir)/qemu
