#!/bin/bash
set -x

../configure \
  --target-list=x86_64-linux-user \
  --cc=clang-16 \
  --host-cc=clang-16 \
  --cxx=clang++-16 \
  --objcc=clang-16 \
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
  --enable-jove

make -j$(nproc)
