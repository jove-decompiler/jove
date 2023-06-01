#!/bin/bash
set -x

# --sysroot=/usr/mipsel-linux-gnu
# --gcc-toolchain=/usr/lib/gcc-cross/mipsel-linux-gnu/12
# -fuse-ld=lld

OURCFLAGS=\
"--target=mipsel-linux-gnu"

cmake -G Ninja \
  -D CMAKE_BUILD_TYPE=Release \
  -D "CMAKE_INSTALL_PREFIX=$(pwd)/../cross_install" \
  -D CMAKE_SYSTEM_NAME=Linux \
  -D CMAKE_CROSSCOMPILING=True \
  -D LLVM_TARGET_ARCH=mipsel \
  -D LLVM_DEFAULT_TARGET_TRIPLE=mipsel-linux-gnu \
  -D LLVM_HOST_TRIPLE=mipsel-linux-gnu \
  -D CMAKE_C_COMPILER=$(which clang) \
  -D CMAKE_CXX_COMPILER=$(which clang++) \
  -D "CMAKE_C_FLAGS=$OURCFLAGS" \
  -D "CMAKE_CXX_FLAGS=$OURCFLAGS" \
  -D "LLVM_TARGETS_TO_BUILD=Mips" \
  -D "JOVE_TARGETS_TO_BUILD=mipsel" \
  -D "LLVM_TABLEGEN=$(pwd)/../install/bin/llvm-tblgen" \
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
  -D LLVM_BUILD_DOCS=OFF \
  -D "CMAKE_EXE_LINKER_FLAGS=-static" \
  -D LLVM_BINUTILS_INCDIR=/usr/include \
  ../llvm
