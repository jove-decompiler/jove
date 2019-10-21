# this just obtains the directory this Makefile resides in
THIRD_PARTY_ROOT_DIR := $(shell cd $(dir $(word $(words $(MAKEFILE_LIST)),$(MAKEFILE_LIST)));pwd)

_LLVM_DIR         := $(THIRD_PARTY_ROOT_DIR)/llvm-project
_LLVM_INSTALL_DIR := $(_LLVM_DIR)/install

all: build-llvm

.PHONY: build-llvm
build-llvm:
	cd llvm-project && cmake llvm -G Ninja -D CMAKE_BUILD_TYPE=Release -D "CMAKE_INSTALL_PREFIX=$(_LLVM_INSTALL_DIR)" -D PYTHON_EXECUTABLE=/usr/bin/python -D "LLVM_ENABLE_PROJECTS=llvm;clang;lld;compiler-rt" -D LLVM_ENABLE_RTTI=ON -D LLVM_BUILD_TESTS=OFF -D LLVM_INCLUDE_TESTS=OFF -D LLVM_INCLUDE_EXAMPLES=OFF -D LLVM_BUILD_DOCS=OFF -D LLVM_BINUTILS_INCDIR=/usr/include -D LLVM_ENABLE_BINDINGS=OFF -D LLVM_ENABLE_Z3_SOLVER=OFF -D LLVM_INCLUDE_BENCHMARKS=OFF -D LLVM_TARGETS_TO_BUILD=X86 -D LLVM_USE_LINKER=gold -D LLVM_ENABLE_LTO=OFF && ninja install
