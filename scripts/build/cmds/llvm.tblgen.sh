#!/bin/false

thedir="tblgen_build"

cmds+=("pushd \"$llvm_path\" && mkdir -p $thedir && cd $thedir && retry \"$build_scripts_path/build_llvm.sh -a ${hostarch} -T\" && popd")
