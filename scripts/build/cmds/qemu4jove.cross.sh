#!/bin/false

for arch in $archs; do
  cmds+=("pushd \"$qemu_path\" && mkdir -p ${hostarch}_carbon_build_${arch} && cd ${hostarch}_carbon_build_${arch} && retry \"$build_scripts_path/qemu/build_${hostarch}.sh _carbon $arch\" && popd")
done
