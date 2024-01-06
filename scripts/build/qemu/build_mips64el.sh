#!/bin/bash
trap 'exit' ERR
set -x

TRIPLE="mips64el-linux-gnuabi64"

OURCFLAGS=\
"--target=$TRIPLE"

EXTRACONF="--enable-jove"

if test "$#" = 1 ; then
  if test "$1" = "_carbon" ; then
    EXTRACONF="--enable-jove-helpers"
  fi
fi

if [ ! -f build.ninja ]; then

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

fi

ninja
