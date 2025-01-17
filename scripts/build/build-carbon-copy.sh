#!/bin/bash
set -x

cd /jove/carbon-copy
mkdir build && cd build




cmake -G Ninja -D CMAKE_C_COMPILER=$(which clang-19) -D CMAKE_CXX_COMPILER=$(which clang++-19) -D CMAKE_BUILD_TYPE=Release ..

ninja
