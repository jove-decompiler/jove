#!/bin/false

for arch in $archs; do
  thedir="${arch}_build"
  cmds+=("pushd \"$llvm_path\" && mkdir -p $thedir && cd $thedir && retry \"$build_scripts_path/llvm/build_${arch}.sh\" && popd")
done
