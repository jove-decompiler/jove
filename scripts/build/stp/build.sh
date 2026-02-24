#!/bin/bash
set -e
set -o pipefail
set -x

stp_build_scripts_path=$(cd "$(dirname -- "$0")"; pwd)

if [ ! -f build.ninja ]; then

OURCFLAGS=\
" -O3"\
" -g"\
" -fuse-ld=lld"

cmake -G Ninja \
      -D CMAKE_BUILD_TYPE=RelWithDebInfo \
      -D CMAKE_C_COMPILER=$(which clang-19) \
      -D CMAKE_CXX_COMPILER=$(which clang++-19) \
      -D "CMAKE_C_FLAGS_RELWITHDEBINFO=$OURCFLAGS" \
      -D "CMAKE_CXX_FLAGS_RELWITHDEBINFO=$OURCFLAGS" \
      -S $(pwd)/.. -B $(pwd)

fi

ninja
sudo ninja install
