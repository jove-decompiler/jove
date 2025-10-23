#!/bin/false

for arch in $archs; do
  cmds+=("pushd \"$qemu_path\" && mkdir -p ${arch}_carbon_build && cd ${arch}_carbon_build && retry \"$build_scripts_path/qemu/build_${arch}.sh _carbon\" && popd")
done
