#!/bin/bash

TRIPLE="mips64el-linux-gnuabi64"

OURCFLAGS=\
"--target=$TRIPLE"

EXTRACONF="--enable-jove"

if test "$#" = 1 ; then
  if test "$1" = "helpers" ; then
    OURCFLAGS+=" -Xclang -load -Xclang $(pwd)/../../../carbon-copy/build/collect/libcarbon-collect.so -Xclang -add-plugin -Xclang carbon-collect -Xclang -plugin-arg-carbon-collect -Xclang $(pwd)/.. -Xclang -plugin-arg-carbon-collect -Xclang $(pwd)"
    EXTRACONF="--enable-jove-helpers"
  fi
fi

set -x
../configure \
  --target-list=mips64el-linux-user \
  --cc=clang-16 \
  --host-cc=clang-16 \
  --cxx=clang++-16 \
  --objcc=clang-16 \
  --disable-werror \
  --extra-cflags="$OURCFLAGS" \
  --cross-prefix=mips64el-linux-gnuabi64- \
  --cpu=mips \
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
  $EXTRACONF

make -j$(nproc)
