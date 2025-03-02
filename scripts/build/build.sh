#!/bin/bash
set -e
set -o pipefail
set -x

# Maximum number of retries for each build
MAX_RETRIES=5

# Retry function for building. Why? because clang-19 segfaults :(
retry5() {
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
retry5 $build_scripts_path/wine/build64.sh
popd

pushd .
mkdir -p build && cd build
retry5 $build_scripts_path/wine/build.sh
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
  ln -sf ${hostarch}_build build

  for arch in $archs ; do
    pushd .

    mkdir -p ${arch}${2}_build && cd ${arch}${2}_build
    retry5 "$build_scripts_path/$1/build_${arch}.sh $2"

    popd
  done
}

pushd .

cd $qemu_path
build_all_variants qemu _carbon
build_all_variants qemu

cd $llvm_path
build_all_variants llvm

cd $linux_path
build_all_variants linux _carbon

pushd .
cd $linux_path
retry5 $build_scripts_path/linux/build.sh
popd

popd

retry5 "make -C $jove_path -j$(nproc)"
