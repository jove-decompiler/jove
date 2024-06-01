#!/bin/bash
set -x

cd /jove/carbon-copy
mkdir build && cd build

cmake -G Ninja -D CMAKE_BUILD_TYPE=Release -D CMAKE_INSTALL_PREFIX=/usr/local ..

ninja install
