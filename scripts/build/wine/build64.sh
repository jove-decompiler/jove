#!/bin/bash
set -e 
set -o pipefail
set -x

# gstreamer not enabled because we cannot have development files for 32 and 64
../configure --prefix=/usr --libdir=/usr/lib --with-x --with-wayland --with-vulkan --enable-win64

#make -j$(nproc)
