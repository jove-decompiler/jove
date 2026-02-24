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

cmake -G Ninja \
      -D CMAKE_BUILD_TYPE=RelWithDebInfo \
      -D CMAKE_C_COMPILER=$(which clang-19) \
      -D CMAKE_CXX_COMPILER=$(which clang++-19) \
      -D "CMAKE_C_FLAGS_RELWITHDEBINFO=$OURCFLAGS" \
      -D "CMAKE_CXX_FLAGS_RELWITHDEBINFO=$OURCFLAGS" \
      -D ENABLE_SOLVER_STP=ON \
      -D ENABLE_SOLVER_Z3=OFF \
      -D ENABLE_POSIX_RUNTIME=OFF \
      -D ENABLE_SYSTEM_TESTS=OFF \
      -D ENABLE_UNIT_TESTS=OFF \
      -D ENABLE_KLEE_ASSERTS=ON \
      -D ENABLE_DOCS=OFF \
      -D LLVM_ENABLE_EH=OFF \
      -D LLVM_ENABLE_LTO=THIN \
      -D LLVM_USE_LINKER=lld \
      -D LLVM_DIR=$klee_build_scripts_path/../../../llvm-project/build/llvm/lib/cmake/llvm \
      -D LLVM_CONFIG_BINARY=$klee_build_scripts_path/../../../llvm-project/build/llvm/bin/llvm-config \
      -D LLVMCC=$klee_build_scripts_path/../../../llvm-project/build/llvm/bin/clang \
      -D LLVMCXX=$klee_build_scripts_path/../../../llvm-project/build/llvm/bin/clang++ \
      -S $(pwd)/.. -B $(pwd)

fi

ninja
