#!/bin/false

for arch in "${all_archs[@]}"; do
  thedir="${arch}_carbon_build"

  cross=""
  if [ "$arch" != "$hostarch" ]; then
    cross=" -C"
  fi

  cmds+=("pushd \"$qemu_path\" && mkdir -p $thedir && cd $thedir && retry \"$build_scripts_path/build_qemu.sh -a ${arch} -c${cross}\" && popd")
done
