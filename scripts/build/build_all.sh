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
mkdir -p                "$llvm_path/llvm/projects"

rm -f                   "$llvm_path/llvm/projects/jove"
ln -s ../../..          "$llvm_path/llvm/projects/jove"

rm -f                   "$llvm_path/llvm/projects/llvm-cbe"
ln -s ../../../llvm-cbe "$llvm_path/llvm/projects/llvm-cbe"

rm -f                   "$qemu_path/build"
ln -s ${hostarch}_build "$qemu_path/build"

rm -f                   "$llvm_path/build"
ln -s ${hostarch}_build "$llvm_path/build"

# convenience
X="$build_scripts_path"
Y="$cmdsdir"

# -------- Stage 1 --------
. "$Y/carbon-copy.sh"
. "$Y/llknife.19.sh"

. "$X/parallel.sh"

# -------- Stage 2 --------
. "$Y/wine64.sh"
. "$Y/linux.sh"
. "$Y/qemu.helpers.sh"
. "$Y/qemu4jove.sh"
. "$Y/qemu4jove.cross.sh"

. "$X/parallel.sh"

# -------- Stage 3 --------
. "$Y/03_make.sh"
. "$Y/llvm.tblgen.sh"
. "$Y/minisat.sh"

. "$X/parallel.sh"

# -------- Stage 4 --------
. "$Y/wine32.sh"
. "$Y/llvm.sh"
. "$Y/stp.sh"

. "$X/parallel.sh"

# -------- Stage 5 --------
. "$Y/llknife.sh"
. "$Y/qemu.softfpu.sh"
. "$Y/klee.sh"

. "$X/parallel.sh"

# -------- Stage 6 --------
. "$Y/06_make.sh"
. "$X/parallel.sh"

# -------- Stage 7 --------
. "$Y/07_make.sh"
. "$X/parallel.sh"
