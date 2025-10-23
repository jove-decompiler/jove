#!/bin/false

for arch in $archs; do
  cmds+=("pushd \"$qemu_path\" && mkdir -p ${arch}_build && cd ${arch}_build && retry \"$build_scripts_path/qemu/build_${arch}.sh\" && popd")
done
