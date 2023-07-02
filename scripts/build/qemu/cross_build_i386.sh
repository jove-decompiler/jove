#!/bin/bash
set -x

../configure \
  --cc=$(which clang-15) \
  --host-cc=$(which clang-15) \
  --cxx=$(which clang++-15) \
  --objcc=$(which clang-15) \
  --disable-werror \
  --target-list=i386-linux-user \
  --cross-prefix=i686-linux-gnu- \
  --cpu=i386 \
  --enable-tcg-interpreter \
  --disable-docs \
  --disable-install-blobs \
  --disable-qom-cast-debug \
  --disable-vhost-kernel \
  --disable-vhost-net \
  --disable-vhost-user \
  --disable-vhost-crypto \
  --disable-vhost-vdpa \
  --disable-plugins \
  --disable-stack-protector \
  --enable-jove
