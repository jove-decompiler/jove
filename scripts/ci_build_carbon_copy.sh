#!/bin/bash
set -e
set -o pipefail

pushd .

cd /jove/carbon-copy
rm -rf build && mkdir build && cd build

CC=clang-19 CXX=clang++-19 cmake -G Ninja -D CMAKE_BUILD_TYPE=Release -D CMAKE_INSTALL_PREFIX=/usr/local -S $(pwd)/.. -B $(pwd)

ninja install

popd

# clear build directory
rm -rf /jove/carbon-copy/build
