#!/bin/false

thedir="${hostarch}_build"

cmds+=("pushd \"$llvm_path\" && mkdir -p $thedir && cd $thedir && retry \"$build_scripts_path/llvm/build_${hostarch}.sh tblgen\" && popd")
