#!/bin/bash
set -x

cd /jove/carbon-copy
mkdir build && cd build

CXX=clang++-16 cmake -G Ninja -D CMAKE_BUILD_TYPE=Release ..

ninja
