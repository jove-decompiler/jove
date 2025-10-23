#!/bin/false

for arch in $archs; do
  thedir="${hostarch}_carbon_build_${arch}"
  cmds+=("pushd \"$qemu_path\" && mkdir -p $thedir && cd $thedir && retry \"$build_scripts_path/qemu/build_${hostarch}.sh _carbon $arch\" && popd")
done
