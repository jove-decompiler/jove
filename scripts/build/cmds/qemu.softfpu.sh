#!/bin/false

for arch in "${all_archs[@]}"; do
  thedir="${arch}_softfpu_linux_build"

  cross=""
  if [ "$arch" != "$hostarch" ]; then
    cross=" -C"
  fi

  cmds+=("pushd \"$qemu_path\" && mkdir -p $thedir && cd $thedir && retry \"$build_scripts_path/build_qemu.sh -a ${arch} -s${cross} _linux\" && popd")
done

for arch in "${all_archs[@]}"; do
  thedir="${arch}_softfpu_win_build"

  cross=""
  if [ "$arch" != "$hostarch" ]; then
    cross=" -C"
  fi

  cmds+=("pushd \"$qemu_path\" && mkdir -p $thedir && cd $thedir && retry \"$build_scripts_path/build_qemu.sh -a ${arch} -s${cross} _win\" && popd")
done
