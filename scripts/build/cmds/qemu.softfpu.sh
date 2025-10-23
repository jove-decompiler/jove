#!/bin/false

for arch in $archs; do
  thedir="${arch}_softfpu_linux_build"
  cmds+=("pushd \"$qemu_path\" && mkdir -p $thedir && cd $thedir && retry \"$build_scripts_path/qemu/build_${arch}.sh _softfpu _linux\" && popd")
done

for arch in $archs; do
  thedir="${arch}_softfpu_win_build"
  cmds+=("pushd \"$qemu_path\" && mkdir -p $thedir && cd $thedir && retry \"$build_scripts_path/qemu/build_${arch}.sh _softfpu _win\" && popd")
done
