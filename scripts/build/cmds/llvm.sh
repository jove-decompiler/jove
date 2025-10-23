#!/bin/false

for arch in $archs; do
  cmds+=("pushd \"$llvm_path\" && mkdir -p ${arch}_build && cd ${arch}_build && retry \"$build_scripts_path/llvm/build_${arch}.sh\" && popd")
done
