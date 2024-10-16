#!/bin/bash

set -e
set -o pipefail
set -x

scripts_path=$(cd "$(dirname -- "$0")"; pwd)
linux_path=$scripts_path/../linux-upstream

archs="x86_64 i386 mipsel mips64el aarch64"

alter_config() {
  sed -i 's/^CONFIG_PREEMPT_BUILD=.*/CONFIG_PREEMPT_BUILD=n/' .config
  sed -i 's/^CONFIG_PREEMPT_DYNAMIC=.*/CONFIG_PREEMPT_DYNAMIC=n/' .config
  sed -i 's/^CONFIG_PREEMPT_DYNAMIC=.*/CONFIG_PREEMPT_DYNAMIC=n/' .config
}


distclean() {
  make ARCH=$1 CC=clang distclean
}

config() {
  make ARCH=$1 CC=clang $2
}

function x86_64_build() {
  make CC=clang distclean
  #cp ~/jove/bin/x86_64/.config .config
  make CC=clang x86_64_defconfig
  make CC=clang "$1"
}

function i386_build() {
  make CC=clang distclean
  #cp ~/jove/bin/i386/.config .config
  make CC=clang i386_defconfig
  make CC=clang "$1"
}

function mipsel_build() {
  make CC=clang ARCH=mips distclean
  #cp ~/jove/bin/mipsel/.config .config
  make CC=clang ARCH=mips malta_defconfig
  make CC=clang ARCH=mips "$1"
}

function mips64el_build() {
  make CC=clang ARCH=mips distclean
  #cp ~/jove/bin/mips64el/.config .config
  make CC=clang ARCH=mips 64r2el_defconfig BOARDS=boston
  make CC=clang ARCH=mips BOARDS=boston "$1"
}

function aarch64_build() {
  make CC=clang ARCH=arm64 LD=ld.lld OBJCOPY=llvm-objcopy distclean
  #cp ~/jove/bin/aarch64/.config .config
  make CC=clang ARCH=arm64 LD=ld.lld OBJCOPY=llvm-objcopy defconfig
  make CC=clang ARCH=arm64 LD=ld.lld OBJCOPY=llvm-objcopy "$1"
}

function extract() {
  # lib/list_sort.c:290l 
  # kernel/locking/spinlock.c:452l
  carbon-extract --src "$linux_path" --bin "$linux_path" --debug lib/list_sort.c:290l > ~/jove/bin/$1/linux.copy.h
}

pushd .

cd "$linux_path"

for arch in $archs ; do
  rm -rf .carbon

  # kernel/locking/spinlock.o
  # lib/list_sort.o

  ${arch}_build lib/list_sort.o
  extract $arch

  sudo cp ~/jove/bin/$arch/linux.copy.h /var/lib/machines/deb64-container/home/aeden/jove/bin/$arch/
done

popd
