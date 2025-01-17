#!/bin/bash
set -x

cd ~/jove/carbon-copy
mkdir build && cd build

CC=clang-19 CXX=clang++-19 cmake -G Ninja -D CMAKE_BUILD_TYPE=Release -S $(pwd)/.. -B $(pwd)

ninja
