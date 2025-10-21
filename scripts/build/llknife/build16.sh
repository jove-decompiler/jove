#!/bin/bash
set -e 
set -o pipefail
set -x

llknife_build_scripts_path=$(cd "$(dirname -- "$0")"; pwd)

if [ ! -f build.ninja ]; then

CC=clang-19 CXX=clang++-19 LDFLAGS="-fuse-ld=lld" cmake -G Ninja -D CMAKE_BUILD_TYPE=RelWithDebInfo -D LLVM_ENABLE_ASSERTIONS=ON -D LLVM_DIR=$llknife_build_scripts_path/../../../llvm-project/build/llvm/lib/cmake/llvm -S $(pwd)/.. -B $(pwd)

fi

ninja
sudo ninja install
