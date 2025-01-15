#!/bin/bash
set -e 
set -o pipefail
set -x

if [ ! -f Makefile ]; then

PKG_CONFIG_PATH=/usr/lib/i386-linux-gnu/pkgconfig ../configure --prefix=/usr --with-x --with-wayland --with-gstreamer --libdir=/usr/lib32 --with-vulkan --with-wine64=$(pwd)/../build64

fi

make -j$(nproc)
