# this just obtains the directory this Makefile resides in
ROOT_DIR := $(shell cd $(dir $(word $(words $(MAKEFILE_LIST)),$(MAKEFILE_LIST)));pwd)

qemutcg_archs  := x86_64 i386 arm aarch64
qemu_build_dir := /home/aeden/Hacking/qemu-2.5.0-build
qemu_src_dir   := /home/aeden/Hacking/qemu-2.5.0
llvm_build_dir := /home/aeden/Hacking/llvm-3.8.0-build
opam_libs_dir  := ~/.opam/system/lib
ocaml_dir      := /usr/lib/ocaml

build_dir      := $(ROOT_DIR)/build
