#!/bin/bash
set -e 
set -o pipefail
set -x

if [ ! -f build.ninja ]; then

CC=clang CXX=clang++ LDFLAGS="-fuse-ld=lld" cmake -G Ninja -D CMAKE_BUILD_TYPE=RelWithDebInfo -D LLVM_ENABLE_ASSERTIONS=ON -S $(pwd)/.. -B $(pwd)

fi

ninja
sudo ninja install
