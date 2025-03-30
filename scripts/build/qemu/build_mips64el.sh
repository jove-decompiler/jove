#!/bin/bash
set -e 
set -o pipefail
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

AR=llvm-ar-19 RANLIB=llvm-ranlib-19 LD=ld.lld-19 ../configure \
  --target-list=mips64el-linux-user \
  --cc=clang-19 \
  --host-cc=clang-19 \
  --cxx=clang++-19 \
  --objcc=clang-19 \
  --disable-werror \
  --extra-cflags="$OURCFLAGS" \
  --cross-prefix=mips64el-linux-gnuabi64- \
  --cpu=mips \
  --enable-tcg-interpreter \
  --enable-lto \
  --enable-tools \
  --disable-docs \
  --disable-install-blobs \
  --disable-qom-cast-debug \
  --disable-vhost-kernel \
  --disable-vhost-net \
  --enable-vhost-user \
  --disable-vhost-crypto \
  --disable-vhost-vdpa \
  --disable-plugins \
  --disable-stack-protector \
  --disable-capstone \
  --disable-libdw \
  $EXTRACONF

fi

ninja
