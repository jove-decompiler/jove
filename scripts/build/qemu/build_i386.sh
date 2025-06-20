#!/bin/bash
set -e 
set -o pipefail
set -x

EXTRACONF="--enable-jove"

THE_CC=clang-19
THE_CXX=clang++-19
THE_AR=llvm-ar-19
THE_RANLIB=llvm-ranlib-19
THE_LD=ld.lld-19

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
  --target-list=i386-linux-user \
  --cc=$THE_CC \
  --host-cc=$THE_CC \
  --cxx=$THE_CXX \
  --objcc=$THE_CC \
  --disable-werror \
  --cross-prefix=i686-linux-gnu- \
  --cpu=i386 \
  --enable-tcg-interpreter \
  --enable-tcg \
  --disable-plugins \
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
  --enable-trace-backends=nop \
  $EXTRACONF

fi

make -j$(nproc)
