#!/bin/false

for arch in $archs; do
  thedir="${arch}_carbon_build"
  cmds+=("pushd \"$linux_path\" && mkdir -p $thedir && cd $thedir && retry \"$build_scripts_path/linux/build_${arch}.sh _carbon\" && popd")
done
