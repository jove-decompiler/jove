#!/bin/bash

TRIPLE="mips64el-linux-gnuabi64"

OURCFLAGS=\
"--target=$TRIPLE"
CONFFLAGS="--enable-jove"

if test "$#" = 1 ; then
  if test "$1" = "helpers" ; then
    OURCFLAGS+=" -Xclang -load -Xclang $HOME/carbon-copy/build/collect/libcarbon-collect.so -Xclang -add-plugin -Xclang carbon-collect -Xclang -plugin-arg-carbon-collect -Xclang $(pwd)/.. -Xclang -plugin-arg-carbon-collect -Xclang $(pwd)"
    CONFFLAGS="--enable-jove-helpers"
  fi
fi

set -x
../configure \
  --cc=$(which clang-15) \
  --host-cc=$(which clang-15) \
  --cxx=$(which clang++-15) \
  --objcc=$(which clang-15) \
  --disable-werror \
  --extra-cflags="$OURCFLAGS" \
  --target-list=mips64el-linux-user \
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
  $CONFFLAGS
