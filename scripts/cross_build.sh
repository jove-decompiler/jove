#!/bin/bash
set -x

cmake ~/jove/llvm-project/llvm -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_SYSTEM_NAME=Linux \
  -DCMAKE_CROSSCOMPILING=True \
  -DLLVM_TARGET_ARCH=mipsel \
  -DLLVM_DEFAULT_TARGET_TRIPLE=mipsel-linux-gnu \
  -DLLVM_HOST_TRIPLE=mipsel-linux-gnu \
  -DCMAKE_C_COMPILER=/usr/bin/mipsel-linux-gnu-gcc \
  -DCMAKE_CXX_COMPILER=/usr/bin/mipsel-linux-gnu-g++ \
  -DLLVM_TARGETS_TO_BUILD=Mips \
  -DLLVM_TABLEGEN=/usr/bin/llvm-tblgen-11 \
  -DLLVM_BUILD_TESTS=OFF \
  -DLLVM_INCLUDE_TESTS=OFF \
  -DLLVM_ENABLE_BINDINGS=OFF \
  "-DLLVM_ENABLE_PROJECTS=compiler-rt;clang;lld" \
  -DLLVM_ENABLE_RTTI=ON \
  -DLLVM_ENABLE_ASSERTIONS=ON \
  -DLLVM_ENABLE_EH=ON \
  -DLLVM_BUILD_DOCS=OFF \
  -DLLVM_BINUTILS_INCDIR=/usr/include \
  -DLLVM_ENABLE_PIC=ON \
  -DLLVM_ENABLE_Z3_SOLVER=OFF
