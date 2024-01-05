#!/bin/bash

EXTRACONF="--enable-jove"

if test "$#" = 1 ; then
  if test "$1" = "_carbon" ; then
    EXTRACONF="--enable-jove-helpers"
  fi
fi

set -x

../configure \
  --target-list=i386-linux-user \
  --cc=clang-16 \
  --host-cc=clang-16 \
  --cxx=clang++-16 \
  --objcc=clang-16 \
  --disable-werror \
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
  $EXTRACONF

make -j$(nproc)
