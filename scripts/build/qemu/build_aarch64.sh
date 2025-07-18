#!/bin/bash
set -e 
set -o pipefail
set -x

TRIPLE="aarch64-linux-gnu"

OURCFLAGS=\
"--target=$TRIPLE"

THE_CC=clang-19
THE_CXX=clang++-19
THE_AR=llvm-ar-19
THE_RANLIB=llvm-ranlib-19
THE_LD=ld.lld-19

EXTRACONF="--enable-jove"

if test "$#" -ge 1 ; then
  if test "$1" = "_carbon" ; then
    EXTRACONF="--enable-jove-helpers"
  fi
  if test "$1" = "_softfpu" ; then
    EXTRACONF="--enable-jove-helpers"
    THE_CC=$(pwd)/../../llvm-project/build/llvm/bin/clang
    THE_CXX=$(pwd)/../../llvm-project/build/llvm/bin/clang++
    THE_AR=$(pwd)/../../llvm-project/build/llvm/bin/llvm-ar
    THE_RANLIB=$(pwd)/../../llvm-project/build/llvm/bin/llvm-ranlib
    THE_LD=$(pwd)/../../llvm-project/build/llvm/bin/ld.lld
  fi
  if test "$2" = "_win" ; then
    : # EXTRACONF+=" --enable-ms-bitfields"
  fi
fi

if [ ! -f build.ninja ]; then

AR=$THE_AR RANLIB=$THE_RANLIB LD=$THE_LD ../configure \
  --target-list=aarch64-linux-user \
  --cc=$THE_CC \
  --host-cc=$THE_CC \
  --cxx=$THE_CXX \
  --objcc=$THE_CC \
  --disable-werror \
  --extra-cflags="$OURCFLAGS" \
  --cross-prefix=aarch64-linux-gnu- \
  --cpu=aarch64 \
  --enable-tcg-interpreter \
  --enable-tcg \
  --disable-plugins \
  --enable-lto \
  --enable-pie \
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
  --enable-trace-backends=nop \
  $EXTRACONF

fi

ninja
