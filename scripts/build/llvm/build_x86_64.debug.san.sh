#!/bin/bash
set -e 
set -o pipefail
set -x

if [ ! -f build.ninja ]; then

cmake -G Ninja \
      -D CMAKE_BUILD_TYPE=Debug \
      -D CMAKE_C_COMPILER=$(which clang-16) \
      -D CMAKE_CXX_COMPILER=$(which clang++-16) \
      -D "LLVM_TARGETS_TO_BUILD=Mips;X86;AArch64" \
      -D "JOVE_TARGETS_TO_BUILD=i386;x86_64;mipsel;mips64el;aarch64" \
      -D JOVE_HAVE_MEMFD=ON \
      -D "LLVM_TABLEGEN=$(pwd)/../build/bin/llvm-tblgen" \
      -D LLVM_BUILD_TESTS=OFF \
      -D LLVM_INCLUDE_TESTS=OFF \
      -D LLVM_ENABLE_BINDINGS=OFF \
      -D "LLVM_ENABLE_PROJECTS=clang;lld" \
      -D LLVM_ENABLE_PEDANTIC=OFF \
      -D LLVM_ENABLE_RTTI=ON \
      -D LLVM_ENABLE_LIBXML2=OFF \
      -D LLVM_ENABLE_TERMINFO=OFF \
      -D LLVM_ENABLE_ZSTD=OFF \
      -D LLVM_ENABLE_ZLIB=ON \
      -D LLVM_ENABLE_ASSERTIONS=ON \
      -D LLVM_ENABLE_EH=ON \
      -D LLVM_BUILD_DOCS=OFF \
      -D LLVM_BINUTILS_INCDIR=/usr/include \
      -D LLVM_ENABLE_PIC=ON \
      -D LLVM_ENABLE_Z3_SOLVER=OFF \
      -D JOVE_USE_SYSTEM_TBB=ON \
      -D "LLVM_USE_SANITIZER=Address;Undefined" \
      -D LLVM_ENABLE_LTO=OFF \
      -D LLVM_USE_LINKER=lld \
      ../llvm

fi

ninja include/llvm/IR/Attributes.inc && ninja bin/jove-{x86_64,i386,aarch64,mipsel,mips64el}
