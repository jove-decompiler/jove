#!/usr/bin/env bash
set -e
set -o pipefail
set -x

# Same positional-arg semantics
if (( $# >= 1 )); then MAX_RETRIES="$1";   else MAX_RETRIES=1; fi
if (( $# >= 2 )); then PARALLEL_JOBS="$2"; else PARALLEL_JOBS=$(nproc); fi

archs="x86_64 i386 mipsel mips64el aarch64"
hostarch="x86_64"

#
# locate stuff
#
build_scripts_path=$(cd "$(dirname -- "$0")"; pwd)
export build_scripts_path MAX_RETRIES PARALLEL_JOBS archs hostarch

. "$build_scripts_path/paths.sh"
. "$build_scripts_path/retry.sh"

#
# fresh symlinks
#
rm -f                   "$llvm_path/llvm/projects/jove"
ln -s ../../..          "$llvm_path/llvm/projects/jove"

rm -f                   "$llvm_path/llvm/projects/llvm-cbe"
ln -s ../../../llvm-cbe "$llvm_path/llvm/projects/llvm-cbe"

rm -f                   "$qemu_path/build"
ln -s ${hostarch}_build "$qemu_path/build"

rm -f                   "$llvm_path/build"
ln -s ${hostarch}_build "$llvm_path/build"

# -------- Stage 1 --------
. "$build_scripts_path/cmds/carbon-copy.sh"
. "$build_scripts_path/cmds/llknife.19.sh"

. "$build_scripts_path/parallel.sh"

# -------- Stage 2 --------
. "$build_scripts_path/cmds/wine64.sh"
. "$build_scripts_path/cmds/linux.sh"
. "$build_scripts_path/cmds/qemu.helpers.sh"
. "$build_scripts_path/cmds/qemu4jove.sh"
. "$build_scripts_path/cmds/qemu4jove.cross.sh"

. "$build_scripts_path/parallel.sh"

# -------- Stage 3 --------
. "$build_scripts_path/cmds/03_make.sh"
. "$build_scripts_path/cmds/llvm.tblgen.sh"

. "$build_scripts_path/parallel.sh"

# -------- Stage 4 --------
. "$build_scripts_path/cmds/wine32.sh"
. "$build_scripts_path/cmds/llvm.sh"

. "$build_scripts_path/parallel.sh"

# -------- Stage 5 --------
. "$build_scripts_path/cmds/llknife.sh"
. "$build_scripts_path/cmds/qemu.softfpu.sh"

. "$build_scripts_path/parallel.sh"

# -------- Stage 6 --------
. "$build_scripts_path/cmds/06_make.sh"
. "$build_scripts_path/parallel.sh"

# -------- Stage 7 --------
. "$build_scripts_path/cmds/07_make.sh"
. "$build_scripts_path/parallel.sh"
