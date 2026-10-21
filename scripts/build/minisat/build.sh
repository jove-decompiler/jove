#!/bin/bash
set -e
set -o pipefail
set -x

if [ ! -f build.ninja ]; then

OURCFLAGS=\
" -O3"\
" -g"\
" -fuse-ld=lld"

CC=clang CXX=clang++ cmake -G Ninja \
      -D CMAKE_BUILD_TYPE=RelWithDebInfo \
      -S $(pwd)/.. -B $(pwd)

fi

ninja
sudo ninja install
