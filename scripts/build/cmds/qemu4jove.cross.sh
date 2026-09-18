#!/bin/false

#
# this is weird, but unfortunately necessary, since tcgconstants.h changes
#

for arch in "${all_archs[@]}"; do
  thedir="${hostarch}_carbon_build_${arch}"
  cmds+=("pushd \"$qemu_path\" && mkdir -p $thedir && cd $thedir && retry \"$build_scripts_path/build_qemu.sh -a ${hostarch} -t ${arch} -D -F -c\" && popd")
done
