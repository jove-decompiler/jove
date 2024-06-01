#!/bin/bash
set -e
set -o pipefail

pushd .

cd /jove/carbon-copy
mkdir build && cd build

CXX=clang++-16 cmake -G Ninja -D CMAKE_BUILD_TYPE=Release -D CMAKE_INSTALL_PREFIX=/usr/local ..

ninja install

popd

# clear build directory
rm -rf /jove/carbon-copy/build
