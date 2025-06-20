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

TARGETLIST="i386-linux-user,x86_64-linux-user,mipsel-linux-user,mips-linux-user,mips64el-linux-user,aarch64-linux-user"

if test "$#" -ge 1 ; then
  if test "$1" = "_carbon" ; then
    EXTRACONF="--enable-jove-helpers"
    if test "$#" = 2 ; then
      TARGETLIST="$2-linux-user"
    else
      TARGETLIST="x86_64-linux-user"
    fi
  elif test "$1" = "_softfpu" ; then
    EXTRACONF="--enable-jove-helpers"
    TARGETLIST="x86_64-linux-user"
    THE_CC=$(pwd)/../../llvm-project/build/llvm/bin/clang
    THE_CXX=$(pwd)/../../llvm-project/build/llvm/bin/clang++
    THE_AR=$(pwd)/../../llvm-project/build/llvm/bin/llvm-ar
    THE_RANLIB=$(pwd)/../../llvm-project/build/llvm/bin/llvm-ranlib
    THE_LD=$(pwd)/../../llvm-project/build/llvm/bin/ld.lld
    if test "$2" = "_win" ; then
#     EXTRACONF+=" --enable-ms-bitfields"
    fi
  else
    exit 1
  fi
fi

if [ ! -f build.ninja ]; then

AR=$THE_AR RANLIB=$THE_RANLIB LD=$THE_LD ../configure \
  --target-list=$TARGETLIST \
  --cc=$THE_CC \
  --host-cc=$THE_CC \
  --cxx=$THE_CXX \
  --objcc=$THE_CC \
  --cpu=x86_64 \
  --enable-tcg-interpreter \
  --enable-tcg \
  --disable-plugins \
  --enable-lto \
  --disable-werror \
  --disable-docs \
  --enable-tools \
  --disable-install-blobs \
  --disable-qom-cast-debug \
  --disable-vhost-kernel \
  --disable-vhost-net \
  --enable-vhost-user \
  --disable-vhost-user-blk-server \
  --disable-vhost-crypto \
  --disable-vhost-vdpa \
  --disable-plugins \
  --disable-capstone \
  --disable-stack-protector \
  --disable-capstone \
  --disable-libdw \
  --enable-trace-backends=nop \
  $EXTRACONF

fi

ninja
