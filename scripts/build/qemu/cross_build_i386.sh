#!/bin/bash

OURCFLAGS=""

EXTRACONF="--enable-jove"

if test "$#" = 1 ; then
  if test "$1" = "helpers" ; then
    OURCFLAGS+=" -Xclang -load -Xclang $(pwd)/../../../carbon-copy/build/collect/libcarbon-collect.so -Xclang -add-plugin -Xclang carbon-collect -Xclang -plugin-arg-carbon-collect -Xclang $(pwd)/.. -Xclang -plugin-arg-carbon-collect -Xclang $(pwd)"
    EXTRACONF="--enable-jove-helpers"
  fi
fi

set -x
../configure \
  --target-list=i386-linux-user \
  --cc=clang-15 \
  --host-cc=clang-15 \
  --cxx=clang++-15 \
  --objcc=clang-15 \
  --disable-werror \
  --extra-cflags="$OURCFLAGS" \
  --cross-prefix=i686-linux-gnu- \
  --cpu=i386 \
  --enable-tcg-interpreter \
  --disable-docs \
  --disable-install-blobs \
  --disable-qom-cast-debug \
  --disable-vhost-kernel \
  --disable-vhost-net \
  --disable-vhost-user \
  --disable-vhost-crypto \
  --disable-vhost-vdpa \
  --disable-plugins \
  --disable-stack-protector \
  --disable-capstone \
  --static \
  $EXTRACONF

make -j$(nproc)
