#!/bin/bash
set -e
set -o pipefail
set -x

alter_config() {
  sed -i 's/^CONFIG_PREEMPT_BUILD=.*/CONFIG_PREEMPT_BUILD=n/' .config
  sed -i 's/^CONFIG_PREEMPT_DYNAMIC=.*/CONFIG_PREEMPT_DYNAMIC=n/' .config
}

COMMON_ARGS=\
" WERROR=0"\
" LLVM=-19"\
" CLANG=clang-19"\
" LLVM_CONFIG=llvm-config-19"\
" VF=1"\
" V=12"

if test "$#" = 1 ; then
  if test "$1" = "_carbon" ; then
    if [ ! -f Makefile ]; then
    make -C .. "O=$(pwd)" $COMMON_ARGS JOVE_HELPERS=1 x86_64_defconfig
    alter_config
    fi
    make -C .. "O=$(pwd)" $COMMON_ARGS JOVE_HELPERS=1 lib/jove.o lib/crc32.o

    exit 0
  fi
fi

make -C tools/perf -f Makefile.perf \
     $COMMON_ARGS \
     PYTHON=python3 \
     PYTHON_CONFIG=python3-config \
     BUILD_BPF_SKEL=1 \
     NO_LIBPERL=1 \
     NO_LIBPYTHON=1 \
     NO_SLANG=1 \
     NO_LIBUNWIND=1 \
     NO_LIBNUMA=1 \
     NO_LIBAUDIT=1 \
     NO_LIBCRYPTO=1 \
     NO_LIBBABELTRACE=1 \
     NO_CAPSTONE=1 \
     NO_LZMA=1 \
     NO_LIBTRACEEVENT=1 \
     NO_LIBDW=1 \
     NO_SLANG=1 \
     LIBBPF_STATIC=1 \
     -j$(nproc)
