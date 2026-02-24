#!/bin/false

: "${build_scripts_path:?build_scripts_path must be set}"

cmdsdir="$build_scripts_path/cmds"

jove_path="$build_scripts_path/../.."
qemu_path="$jove_path/qemu"
llvm_path="$jove_path/llvm-project"
minisat_path="$jove_path/minisat"
stp_path="$jove_path/stp"
klee_path="$jove_path/klee"
wine_path="$jove_path/wine"
linux_path="$jove_path/linux"
carbc_path="$jove_path/carbon-copy"
llknife_path="$jove_path/llknife"

export jove_path qemu_path llvm_path wine_path linux_path carbc_path llknife_path
