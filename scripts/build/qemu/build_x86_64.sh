#!/bin/bash
set -e 
set -o pipefail
set -x

TRIPLE="x86_64-linux-gnu"

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

TARGETLIST="i386-linux-user,x86_64-linux-user,mipsel-linux-user,mips-linux-user,mips64el-linux-user,aarch64-linux-user"
BUILDLIST="qemu4jove-aarch64.cut.bc qemu4jove-i386.cut.bc qemu4jove-mips64el.cut.bc qemu4jove-mips.cut.bc qemu4jove-mipsel.cut.bc qemu4jove-x86_64.cut.bc"

if test "$#" -ge 1 ; then
  if test "$1" = "_carbon" ; then
    EXTRACONF="--enable-jove-helpers"
    if test "$#" = 2 ; then
      TARGETLIST="$2-linux-user"
      BUILDLIST="qemu-$2 qemu-$2.bitcode"
    else
      TARGETLIST="x86_64-linux-user"
      BUILDLIST="qemu-x86_64 qemu-x86_64.bitcode"
    fi
  elif test "$1" = "_softfpu" ; then
    EXTRACONF="--enable-jove-helpers"
    TARGETLIST="x86_64-linux-user"
    BUILDLIST="qemu-x86_64 qemu-x86_64.bitcode libfpu_soft-x86_64-linux-user.a"
    CLANGVER=16
    if test "$2" = "_win" ; then
      : # EXTRACONF+=" --enable-ms-bitfields"
    fi
  else
    exit 1
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
  --target-list=$TARGETLIST \
  --cc=$THE_CC \
  --host-cc=$THE_CC \
  --cxx=$THE_CXX \
  --objcc=$THE_CC \
  --disable-werror \
  --extra-cflags="$OURCFLAGS" \
  --extra-ldflags="$OURLDFLAGS" \
  --cpu=x86_64 \
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
