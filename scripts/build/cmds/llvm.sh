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

  cmds+=("pushd \"$llvm_path\" && mkdir -p $thedir && cd $thedir && retry \"$build_scripts_path/build_llvm.sh -a ${arch} -t ${target} -A -F${cross}\" && popd")
done
