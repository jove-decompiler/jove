#!/bin/false

cmds+=("pushd \"$llvm_path\" && mkdir -p ${hostarch}_build && cd ${hostarch}_build && retry \"$build_scripts_path/llvm/build_${hostarch}.sh tblgen\" && popd")
