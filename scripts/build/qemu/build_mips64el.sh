#!/bin/bash
set -e 
set -o pipefail
set -x

TRIPLE="mips64el-linux-gnuabi64"

OURCFLAGS=\
" --target=$TRIPLE"\
" -g"\
" -ggdb"\
" -gz=none"\
" -gdwarf-4"

OURLDFLAGS=\
" -no-pie"\
" -fuse-ld=lld"

CLANGVER=19

EXTRACONF="--enable-jove"

BUILDLIST="qemu4jove-mips64el.cut.bc"

if test "$#" -ge 1 ; then
  if test "$1" = "_carbon" ; then
    EXTRACONF="--enable-jove-helpers"
    BUILDLIST="qemu-mips64el qemu-mips64el.bitcode"
  fi
  if test "$1" = "_softfpu" ; then
    EXTRACONF="--enable-jove-helpers"
    BUILDLIST="qemu-mips64el qemu-mips64el.bitcode libfpu_soft-mips64el-linux-user.a"
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
THE_LINK=llvm-link-$CLANGVER
THE_LD=ld.lld-$CLANGVER

if [ ! -f build.ninja ]; then

AR=$THE_AR RANLIB=$THE_RANLIB LD=$THE_LD ../configure \
  --target-list=mips64el-linux-user \
  --cc=$THE_CC \
  --host-cc=$THE_CC \
  --cxx=$THE_CXX \
  --objcc=$THE_CC \
  --disable-werror \
  --extra-cflags="$OURCFLAGS" \
  --extra-ldflags="$OURLDFLAGS" \
  --cross-prefix=mips64el-linux-gnuabi64- \
  --cpu=mips \
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
  --disable-malloc-trim \
  -Dllvm_ar=$THE_AR \
  -Dllvm_link=$THE_LINK \
  $EXTRACONF

fi

ninja $BUILDLIST
