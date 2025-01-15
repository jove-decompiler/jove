#!/bin/bash
set -e
set -o pipefail

pushd .

cd /jove/linux/tools/perf

make -f Makefile.perf CLANG=clang-16 CC=clang-16 PYTHON=python3 PYTHON_CONFIG=python3-config BUILD_BPF_SKEL=1 DEBUG=1 WERROR=0 V=1 NO_LIBPERL=1 NO_LIBPYTHON=1 NO_SLANG=1 LIBBPF_STATIC=1 NO_LIBUNWIND=1 NO_LIBNUMA=1 NO_LIBAUDIT=1 NO_LIBCRYPTO=1 NO_LIBBABELTRACE=1 NO_CAPSTONE=1 NO_LZMA=1 -j$(nproc)

popd
