#!/bin/bash
set -x
trap 'exit' ERR

build_scripts_path=$(cd "$(dirname -- "$0")"; pwd)
jove_path=$build_scripts_path/../..

qemu_path=$jove_path/qemu
llvm_path=$jove_path/llvm-project

rm -f $llvm_path/llvm/projects/jove
rm -f $llvm_path/llvm/projects/llvm-cbe

ln -sf ../../.. $llvm_path/llvm/projects/jove
ln -sf ../../../llvm-cbe $llvm_path/llvm/projects/llvm-cbe

archs="i386 x86_64 mipsel mips64el aarch64"

pushd .

df -h .

cd $qemu_path
mkdir build && cd build
$build_scripts_path/qemu/build.sh

for arch in $archs ; do
  cd $qemu_path

  df -h .

  mkdir ${arch}_build && cd ${arch}_build
  $build_scripts_path/qemu/build_${arch}.sh
done

df -h .

cd $llvm_path
mkdir build && cd build
$build_scripts_path/llvm/build.sh

for arch in $archs ; do
  cd $llvm_path

  df -h .

  mkdir ${arch}_build && cd ${arch}_build
  $build_scripts_path/llvm/build_${arch}.sh
done

df -h .

popd

make -C $jove_path -j$(nproc)
