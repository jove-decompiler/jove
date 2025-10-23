#!/bin/false

for arch in $archs; do
  thedir="${arch}_carbon_build"
  cmds+=("pushd \"$qemu_path\" && mkdir -p $thedir && cd $thedir && retry \"$build_scripts_path/qemu/build_${arch}.sh _carbon\" && popd")
done
