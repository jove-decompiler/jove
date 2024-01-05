#!/bin/bash

EXTRACONF="--enable-jove"
TARGETLIST="i386-linux-user,x86_64-linux-user,mipsel-linux-user,mips-linux-user,mips64el-linux-user,aarch64-linux-user"

if test "$#" = 1 ; then
  if test "$1" = "_carbon" ; then
    EXTRACONF="--enable-jove-helpers"
    TARGETLIST="x86_64-linux-user"
  fi
fi

set -x

../configure \
  --target-list=$TARGETLIST \
  --cc=clang-16 \
  --host-cc=clang-16 \
  --cxx=clang++-16 \
  --objcc=clang-16 \
  --cpu=x86_64 \
  --enable-tcg-interpreter \
  --disable-werror \
  --disable-docs \
  --disable-install-blobs \
  --disable-qom-cast-debug \
  --disable-vhost-kernel \
  --disable-vhost-net \
  --disable-vhost-user \
  --disable-vhost-crypto \
  --disable-vhost-vdpa \
  --disable-plugins \
  --disable-capstone \
  --disable-stack-protector \
  --disable-capstone \
  $EXTRACONF

make -j$(nproc)
