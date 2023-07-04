#!/bin/bash
set -x

# --sysroot=/usr/mipsel-linux-gnu
# --gcc-toolchain=/usr/lib/gcc-cross/mipsel-linux-gnu/12
# -fuse-ld=lld

#  -D "CMAKE_EXE_LINKER_FLAGS=-static" \

TRIPLE="aarch64-linux-gnu"

OURCFLAGS=\
"--target=$TRIPLE"\
" -gdwarf-4"\
" -g1"

cmake -G Ninja \
  -D CMAKE_BUILD_TYPE=RelWithDebInfo \
  -D CMAKE_SYSTEM_NAME=Linux \
  -D CMAKE_CROSSCOMPILING=True \
  -D LLVM_TARGET_ARCH=aarch64 \
  -D LLVM_DEFAULT_TARGET_TRIPLE=$TRIPLE \
  -D LLVM_HOST_TRIPLE=$TRIPLE \
  -D CMAKE_C_COMPILER=$(which clang-15) \
  -D CMAKE_CXX_COMPILER=$(which clang++-15) \
  -D "CMAKE_C_FLAGS=$OURCFLAGS" \
  -D "CMAKE_CXX_FLAGS=$OURCFLAGS" \
  -D "LLVM_TARGETS_TO_BUILD=AArch64" \
  -D "JOVE_TARGETS_TO_BUILD=aarch64" \
  -D "LLVM_TABLEGEN=$(pwd)/../build/bin/llvm-tblgen" \
  -D LLVM_BUILD_TESTS=OFF \
  -D LLVM_INCLUDE_TESTS=OFF \
  -D "LLVM_ENABLE_PROJECTS=llvm" \
  -D LLVM_ENABLE_RTTI=ON \
  -D LLVM_ENABLE_LIBXML2=OFF \
  -D LLVM_ENABLE_TERMINFO=OFF \
  -D LLVM_ENABLE_Z3_SOLVER=OFF \
  -D LLVM_ENABLE_ASSERTIONS=ON \
  -D LLVM_ENABLE_BINDINGS=OFF \
  -D LLVM_ENABLE_EH=ON \
  -D LLVM_ENABLE_PIC=ON \
  -D LLVM_BUILD_DOCS=OFF \
  -D LLVM_USE_LINKER=lld \
  -D LLVM_BINUTILS_INCDIR=/usr/include \
  ../llvm

ninja bin/jove-aarch64
