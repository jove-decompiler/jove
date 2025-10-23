#!/bin/false

for arch in $archs; do
  cmds+=("pushd \"$qemu_path\" && mkdir -p ${arch}_softfpu_linux_build && cd ${arch}_softfpu_linux_build && retry \"$build_scripts_path/qemu/build_${arch}.sh _softfpu _linux\" && popd")
done

for arch in $archs; do
  cmds+=("pushd \"$qemu_path\" && mkdir -p ${arch}_softfpu_win_build && cd ${arch}_softfpu_win_build && retry \"$build_scripts_path/qemu/build_${arch}.sh _softfpu _win\" && popd")
done
