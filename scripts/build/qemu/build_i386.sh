#!/bin/bash
set -e 
set -o pipefail
set -x

TRIPLE="i686-linux-gnu"

OURCFLAGS=\
" --target=$TRIPLE"\
" -g"\
" -ggdb"\
" -gz=none"\
" -gdwarf-4"

OURLDFLAGS=\
" -no-pie"\
" -latomic"\
" -fuse-ld=lld"

CLANGVER=19

EXTRACONF="--enable-jove"

BUILDLIST="libqemu4jove-i386.a"

if test "$#" -ge 1 ; then
  if test "$1" = "_carbon" ; then
    EXTRACONF="--enable-jove-helpers"
    BUILDLIST="qemu-i386 qemu-i386.bitcode"
  fi
  if test "$1" = "_softfpu" ; then
    EXTRACONF="--enable-jove-helpers"
    BUILDLIST="qemu-i386 qemu-i386.bitcode libfpu_soft-i386-linux-user.a"
    CLANGVER=16
  fi
  if test "$2" = "_win" ; then
    : # EXTRACONF+=" --enable-ms-bitfields"
  fi
fi

THE_CC=clang-$CLANGVER
THE_CXX=clang++-$CLANGVER
THE_AR=llvm-ar-$CLANGVER
THE_RANLIB=llvm-ranlib-$CLANGVER
THE_LD=ld.lld-$CLANGVER

if [ ! -f build.ninja ]; then

AR=$THE_AR RANLIB=$THE_RANLIB LD=$THE_LD ../configure \
  --target-list=i386-linux-user \
  --cc=$THE_CC \
  --host-cc=$THE_CC \
  --cxx=$THE_CXX \
  --objcc=$THE_CC \
  --disable-werror \
  --extra-cflags="$OURCFLAGS" \
  --extra-ldflags="$OURLDFLAGS" \
  --cross-prefix=i686-linux-gnu- \
  --cpu=i386 \
  --enable-tcg-interpreter \
  --enable-tcg \
  --disable-plugins \
  --enable-lto \
  --disable-pie \
  --disable-tools \
  --disable-docs \
  --disable-install-blobs \
  --disable-qom-cast-debug \
  --disable-vhost-kernel \
  --disable-vhost-net \
  --disable-vhost-user \
  --disable-vhost-user-blk-server \
  --disable-vhost-crypto \
  --disable-vhost-vdpa \
  --disable-plugins \
  --disable-stack-protector \
  --disable-capstone \
  --disable-libdw \
  --disable-tpm \
  --disable-keyring \
  --disable-passt \
  --disable-selinux \
  --enable-trace-backends=nop \
  $EXTRACONF

fi

ninja $BUILDLIST
