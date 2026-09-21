#!/bin/bash
set -e
set -o pipefail
set -x

if [ ! -f build.ninja ]; then

CC=clang-19 CXX=clang++-19 cmake -G Ninja \
    -D CMAKE_BUILD_TYPE=Debug \
    -D LLVM_DIR=/usr/lib/llvm-19/lib/cmake/llvm \
    -D LLVM_ENABLE_ASSERTIONS=ON -S $(pwd)/.. -B $(pwd)

fi

ninja
sudo ninja install
