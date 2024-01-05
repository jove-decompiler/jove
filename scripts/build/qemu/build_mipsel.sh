#!/bin/bash
trap 'exit' ERR

TRIPLE="mipsel-linux-gnu"

OURCFLAGS=\
"--target=$TRIPLE"

EXTRACONF="--enable-jove"

if test "$#" = 1 ; then
  if test "$1" = "_carbon" ; then
    EXTRACONF="--enable-jove-helpers"
  fi
fi

export PKG_CONFIG_LIBDIR=/usr/lib/mipsel-linux-gnu/pkgconfig 

set -x

../configure \
  --target-list=mipsel-linux-user \
  --cc=clang-16 \
  --host-cc=clang-16 \
  --cxx=clang++-16 \
  --objcc=clang-16 \
  --disable-werror \
  --extra-cflags="$OURCFLAGS" \
  --cross-prefix=mipsel-linux-gnu- \
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
