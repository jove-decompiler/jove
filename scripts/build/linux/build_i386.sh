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
    make -C .. "O=$(pwd)" $COMMON_ARGS JOVE_HELPERS=1 i386_defconfig
    alter_config
    fi
    make -C .. "O=$(pwd)" $COMMON_ARGS JOVE_HELPERS=1 lib/jove.o lib/crc32.o -j$(nproc)

    exit 0
  fi
fi

exit 1
