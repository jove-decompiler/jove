#!/bin/bash
set -e
set -o pipefail
set -x

klee_build_scripts_path=$(cd "$(dirname -- "$0")"; pwd)

if [ ! -f build.ninja ]; then

OURCFLAGS=\
" -O3"\
" -g"\
" -fuse-ld=lld"

llconfig="$klee_build_scripts_path/../../../llvm-project/build/llvm/bin/llvm-config"

cmake -G Ninja \
      -D CMAKE_BUILD_TYPE=RelWithDebInfo \
      -D CMAKE_C_COMPILER=$(which clang) \
      -D CMAKE_CXX_COMPILER=$(which clang++) \
      -D "CMAKE_C_FLAGS_RELWITHDEBINFO=$OURCFLAGS" \
      -D "CMAKE_CXX_FLAGS_RELWITHDEBINFO=$OURCFLAGS" \
      -D CMAKE_EXE_LINKER_FLAGS="-L$klee_build_scripts_path/../../../gperftools/build" \
      -D ENABLE_TCMALLOC=ON \
      -D ENABLE_SOLVER_STP=ON \
      -D ENABLE_SOLVER_Z3=OFF \
      -D ENABLE_POSIX_RUNTIME=OFF \
      -D ENABLE_SYSTEM_TESTS=OFF \
      -D ENABLE_UNIT_TESTS=OFF \
      -D ENABLE_DOCS=OFF \
      -D "LLVM_ENABLE_ASSERTIONS=$($llconfig --assertion-mode)" \
      -D "ENABLE_KLEE_ASSERTS=$($llconfig --assertion-mode)" \
      -D LLVM_ENABLE_EH=OFF \
      -D LLVM_DIR=$klee_build_scripts_path/../../../llvm-project/build/llvm/lib/cmake/llvm \
      -D LLVMCC=$klee_build_scripts_path/../../../llvm-project/build/llvm/bin/clang \
      -D LLVMCXX=$klee_build_scripts_path/../../../llvm-project/build/llvm/bin/clang++ \
      -S $(pwd)/.. -B $(pwd)

fi

ninja
