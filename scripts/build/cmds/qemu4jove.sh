#!/bin/false

for arch in "${all_archs[@]}"; do
  thedir="${arch}_build"
  target="$arch"
  cross=""

  if [ "$arch" = "$hostarch" ]; then
    target="all"
  else
    cross=" -C"
  fi

  cmds+=("pushd \"$qemu_path\" && mkdir -p $thedir && cd $thedir && retry \"$build_scripts_path/build_qemu.sh -a ${arch} -t ${target} -D -F${cross}\" && popd")
done
