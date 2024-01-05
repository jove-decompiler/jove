#!/bin/bash
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

function build_all_variants() {
  ln -s build_x86_64 build

  for arch in $archs ; do
    pushd .

    mkdir ${arch}_build && cd ${arch}_build
    $build_scripts_path/$1/build_${arch}.sh

    popd
  done
}

pushd .

cd $qemu_path
build_all_variants "qemu"

cd $llvm_path
build_all_variants "llvm"

popd

make -C $jove_path -j$(nproc)
