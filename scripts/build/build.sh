#!/bin/bash
set -e
set -o pipefail
set -x

archs="x86_64 i386 mipsel mips64el aarch64"
hostarch="x86_64"

#
# If you passed an argument, use it as MAX_RETRIES, otherwise default to 1.
#
if (( $# >= 1 )); then
  MAX_RETRIES="$1"
else
  MAX_RETRIES=1
fi

#
# Retry function for building. Why? because clang-19 segfaults :(
#
retry() {
  local command="$1"
  local retries=0

  until (( retries >= MAX_RETRIES )); do
    echo "Attempt $((retries + 1)) for command: $command"
    if eval "$command"; then
      echo "Command succeeded: $command"
      return 0
    fi
    echo "Command failed: $command. Retrying..."
    retries=$((retries + 1))
  done

  echo "All attempts failed for command: $command"
  return 1
}

#
# make this available to parallel
#
export -f retry
export MAX_RETRIES

#
# locate stuff
#
build_scripts_path=$(cd "$(dirname -- "$0")"; pwd)
jove_path=$build_scripts_path/../..
qemu_path=$jove_path/qemu
llvm_path=$jove_path/llvm-project
wine_path=$jove_path/wine
linux_path=$jove_path/linux

#
# fresh symlinks
#
rm -f $llvm_path/llvm/projects/jove
rm -f $llvm_path/llvm/projects/llvm-cbe

ln -sf ../../.. $llvm_path/llvm/projects/jove
ln -sf ../../../llvm-cbe $llvm_path/llvm/projects/llvm-cbe

#
# gather build commands into array (1)
#
cmds=()

#
# wine
#
cmds+=("pushd \"$wine_path\" && mkdir -p build64 && cd build64 && retry \"$build_scripts_path/wine/build64.sh\" && popd")
cmds+=("pushd \"$wine_path\" && mkdir -p build   && cd build   && retry \"$build_scripts_path/wine/build.sh\"   && popd")

#
# linux
#
for arch in $archs; do
  cmds+=("pushd \"$linux_path\" && mkdir -p ${arch}_carbon_build && cd ${arch}_carbon_build && retry \"$build_scripts_path/linux/build_${arch}.sh _carbon\" && popd")
done

#
# qemu (_carbon)
#
for arch in $archs; do
  cmds+=("pushd \"$qemu_path\" && mkdir -p ${arch}_carbon_build && cd ${arch}_carbon_build && retry \"$build_scripts_path/qemu/build_${arch}.sh _carbon\" && popd")
done

#
# qemu
#
for arch in $archs; do
  cmds+=("pushd \"$qemu_path\" && mkdir -p ${arch}_build && cd ${arch}_build && retry \"$build_scripts_path/qemu/build_${arch}.sh\" && popd")
done

#
# qemu cross (_carbon)
#
for arch in $archs; do
  cmds+=("pushd \"$qemu_path\" && mkdir -p ${hostarch}_carbon_build_${arch} && cd ${hostarch}_carbon_build_${arch} && retry \"$build_scripts_path/qemu/build_${hostarch}.sh _carbon $arch\" && popd")
done

#
# run everything in parallel (1)
#
printf "%s\n" "${cmds[@]}" \
  | parallel -j $(nproc) -v --lb --halt soon,fail=1

#
# make steps (1)
#
make -C $jove_path --output-sync utilities tcg-constants asm-offsets version -j$(nproc)

#
# gather build commands into array (2)
#
cmds=()

#
# llvm symlink
#
pushd "$llvm_path"
rm -f build
ln -s "${hostarch}_build" build
popd

#
# build `jove` (i.e. llvm)
#
for arch in $archs; do
  cmds+=("pushd \"$llvm_path\" && mkdir -p ${arch}_build && cd ${arch}_build && retry \"$build_scripts_path/llvm/build_${arch}.sh\" && popd")
done

#
# qemu _softfpu
#
for arch in $archs; do
  cmds+=("pushd \"$qemu_path\" && mkdir -p ${arch}_softfpu_linux_build && cd ${arch}_softfpu_linux_build && retry \"$build_scripts_path/qemu/build_${arch}.sh _softfpu _linux\" && popd")
done

for arch in $archs; do
  cmds+=("pushd \"$qemu_path\" && mkdir -p ${arch}_softfpu_win_build && cd ${arch}_softfpu_win_build && retry \"$build_scripts_path/qemu/build_${arch}.sh _softfpu _win\" && popd")
done

#
# run everything in parallel (2)
#
printf "%s\n" "${cmds[@]}" \
  | parallel -j $(nproc) -v --lb --halt soon,fail=1

#
# final make steps (2)
#
make -C "$jove_path" --output-sync all-helpers-mk env-inits softfpu -j$(nproc)
make -C "$jove_path" --output-sync -j$(nproc)
