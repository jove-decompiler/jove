#!/bin/bash
trap 'exit' ERR
set -x

cmake -G Ninja \
      -D CMAKE_BUILD_TYPE=RelWithDebInfo \
      -D CMAKE_C_COMPILER=$(which clang-16) \
      -D CMAKE_CXX_COMPILER=$(which clang++-16) \
      -D "LLVM_TARGETS_TO_BUILD=Mips;X86;AArch64" \
      -D "JOVE_TARGETS_TO_BUILD=i386;x86_64;mipsel;mips64el;aarch64" \
      -D LLVM_BUILD_TESTS=OFF \
      -D LLVM_INCLUDE_TESTS=OFF \
      -D LLVM_ENABLE_BINDINGS=OFF \
      -D "LLVM_ENABLE_PROJECTS=clang;lld" \
      -D LLVM_ENABLE_PEDANTIC=OFF \
      -D LLVM_ENABLE_RTTI=ON \
      -D LLVM_ENABLE_LIBXML2=OFF \
      -D LLVM_ENABLE_TERMINFO=OFF \
      -D LLVM_ENABLE_ASSERTIONS=ON \
      -D LLVM_ENABLE_EH=ON \
      -D LLVM_BUILD_DOCS=OFF \
      -D LLVM_BINUTILS_INCDIR=/usr/include \
      -D LLVM_ENABLE_PIC=ON \
      -D LLVM_ENABLE_Z3_SOLVER=OFF \
      -D LLVM_ENABLE_LTO=OFF \
      -D "CMAKE_EXE_LINKER_FLAGS=-static" \
      -D LLVM_USE_LINKER=lld \
      ../llvm

ninja
