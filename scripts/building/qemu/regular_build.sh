#!/bin/bash
set -x

../configure --target-list=x86_64-linux-user --cc=clang-15 --host-cc=clang-15 --cxx=clang++-15 --objcc=clang-15 --enable-tcg-interpreter --disable-docs --disable-install-blobs --disable-qom-cast-debug --disable-vhost-kernel --disable-vhost-net --disable-vhost-user --disable-vhost-crypto --disable-vhost-vdpa --disable-plugins --disable-stack-protector --enable-jove
