#!/bin/bash
trap 'exit' ERR
set -x

TRIPLE="i686-linux-gnu"

OURCFLAGS=\
"--target=$TRIPLE"\
" -gline-tables-only"\
" -gdwarf-4"

if [ ! -f build.ninja ]; then

cmake -G Ninja \
  -D CMAKE_BUILD_TYPE=Release \
  -D CMAKE_SYSTEM_NAME=Linux \
  -D CMAKE_CROSSCOMPILING=True \
  -D LLVM_TARGET_ARCH=i386 \
  -D LLVM_DEFAULT_TARGET_TRIPLE=$TRIPLE \
  -D LLVM_HOST_TRIPLE=$TRIPLE \
  -D CMAKE_C_COMPILER=$(which clang-16) \
  -D CMAKE_CXX_COMPILER=$(which clang++-16) \
  -D "CMAKE_C_FLAGS=$OURCFLAGS" \
  -D "CMAKE_CXX_FLAGS=$OURCFLAGS" \
  -D "LLVM_TARGETS_TO_BUILD=X86" \
  -D "JOVE_TARGETS_TO_BUILD=i386" \
  -D "LLVM_TABLEGEN=$(pwd)/../build/bin/llvm-tblgen" \
  -D LLVM_BUILD_TESTS=OFF \
  -D LLVM_INCLUDE_TESTS=OFF \
  -D "LLVM_ENABLE_PROJECTS=llvm" \
  -D LLVM_ENABLE_RTTI=ON \
  -D LLVM_ENABLE_LIBXML2=OFF \
  -D LLVM_ENABLE_TERMINFO=OFF \
  -D LLVM_ENABLE_Z3_SOLVER=OFF \
  -D LLVM_ENABLE_ASSERTIONS=OFF \
  -D LLVM_ENABLE_BINDINGS=OFF \
  -D LLVM_ENABLE_EH=ON \
  -D LLVM_ENABLE_PIC=ON \
  -D LLVM_BUILD_DOCS=OFF \
  -D "CMAKE_EXE_LINKER_FLAGS=-static" \
  -D LLVM_BINUTILS_INCDIR=/usr/include \
  -D LLVM_USE_LINKER=lld \
  ../llvm

fi

ninja bin/jove-i386
