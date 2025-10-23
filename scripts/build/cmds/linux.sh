#!/bin/false

for arch in $archs; do
  cmds+=("pushd \"$linux_path\" && mkdir -p ${arch}_carbon_build && cd ${arch}_carbon_build && retry \"$build_scripts_path/linux/build_${arch}.sh _carbon\" && popd")
done
