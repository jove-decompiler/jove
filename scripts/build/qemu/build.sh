#!/bin/bash
set -x

../configure \
  --target-list=i386-linux-user,x86_64-linux-user,mipsel-linux-user,mips-linux-user,mips64el-linux-user,aarch64-linux-user \
  --cc=clang-15 \
  --host-cc=clang-15 \
  --cxx=clang++-15 \
  --objcc=clang-15 \
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
  --enable-jove || cat config.log

make -j$(nproc)
