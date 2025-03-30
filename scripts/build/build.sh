#!/bin/bash
set -e
set -o pipefail
set -x

# Maximum number of retries for each build
MAX_RETRIES=20

# Retry function for building. Why? because clang-19 segfaults :(
retry() {
  local command="$1"
  local retries=0

  until (( retries >= MAX_RETRIES )); do
    echo "Attempt $((retries + 1)) for command: $command"
    if eval "$command"; then
      echo "Command succeeded: $command"
      return 0
    fi
    echo "Command failed: $command. Retrying..."
    retries=$((retries + 1))
  done

  echo "All attempts failed for command: $command"
  return 1
}

build_scripts_path=$(cd "$(dirname -- "$0")"; pwd)
jove_path=$build_scripts_path/../..

qemu_path=$jove_path/qemu
llvm_path=$jove_path/llvm-project
wine_path=$jove_path/wine
linux_path=$jove_path/linux

pushd .
cd $wine_path

pushd .
mkdir -p build64 && cd build64
retry $build_scripts_path/wine/build64.sh
popd

pushd .
mkdir -p build && cd build
retry $build_scripts_path/wine/build.sh
popd

popd

rm -f $llvm_path/llvm/projects/jove
rm -f $llvm_path/llvm/projects/llvm-cbe

ln -sf ../../.. $llvm_path/llvm/projects/jove
ln -sf ../../../llvm-cbe $llvm_path/llvm/projects/llvm-cbe

archs="x86_64 i386 mipsel mips64el aarch64"
hostarch="x86_64"

function build_all_variants() {
  rm -f build
  ln -sf ${hostarch}${2}_build build

  for arch in $archs ; do
    pushd .

    mkdir -p ${arch}${2}_build && cd ${arch}${2}_build
    retry "$build_scripts_path/$1/build_${arch}.sh $2"

    popd
  done
}

# FIXME rename to something better
function build_all_qemu_variants() {
  for arch in $archs ; do
    pushd .

    mkdir -p ${hostarch}${1}_build_${arch} && cd ${hostarch}${1}_build_${arch}
    retry "$build_scripts_path/qemu/build_${hostarch}.sh $1 $arch"

    popd
  done
}

pushd .
cd $qemu_path
build_all_variants qemu _carbon
build_all_variants qemu

build_all_qemu_variants _carbon
popd

pushd .
cd $linux_path
build_all_variants linux _carbon
popd

make -C $jove_path --output-sync all-helpers-mk -j$(nproc)
make -C $jove_path --output-sync asm-offsets -j$(nproc)
make -C $jove_path --output-sync utilities -j$(nproc)
make -C $jove_path --output-sync tcg-constants -j$(nproc)

pushd .
cd $llvm_path
build_all_variants llvm
popd

retry "make -C $jove_path -j$(nproc)"
