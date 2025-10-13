#!/bin/bash
set -e
set -o pipefail
set -x

#
# "Endless AddressSanitizer:DEADLYSIGNAL loop"
# https://reviews.llvm.org/D148280
#
# $ sudo sysctl vm.mmap_rnd_bits=28
#
# and down below we are turning LLVM_ENABLE_PIC=OFF with the hope that it will
# improve the situation
#

if [ ! -f build.ninja ]; then

OURCFLAGS=\
" -Og"\
" -g1"\
" -ggdb"\
" -fno-omit-frame-pointer"\
" -mno-omit-leaf-frame-pointer"

cmake -G Ninja \
      -D CMAKE_BUILD_TYPE=RelWithDebInfo \
      -D CMAKE_C_COMPILER=$(which clang-19) \
      -D CMAKE_CXX_COMPILER=$(which clang++-19) \
      -D "CMAKE_C_FLAGS_RELWITHDEBINFO=$OURCFLAGS" \
      -D "CMAKE_CXX_FLAGS_RELWITHDEBINFO=$OURCFLAGS" \
      -D "LLVM_TARGETS_TO_BUILD=Mips;X86;AArch64" \
      -D "JOVE_TARGETS_TO_BUILD=i386;x86_64;mipsel;mips64el;aarch64" \
      -D "LLVM_TABLEGEN=$(pwd)/../build/llvm/bin/llvm-tblgen" \
      -D "CLANG_TABLEGEN=$(pwd)/../build/llvm/bin/clang-tblgen" \
      -D LLVM_BUILD_TESTS=OFF \
      -D LLVM_INCLUDE_TESTS=OFF \
      -D LLVM_ENABLE_BINDINGS=OFF \
      -D "LLVM_ENABLE_PROJECTS=clang;lld" \
      -D LLVM_ENABLE_PEDANTIC=OFF \
      -D LLVM_ENABLE_RTTI=ON \
      -D LLVM_ENABLE_LIBXML2=OFF \
      -D LLVM_ENABLE_TERMINFO=OFF \
      -D LLVM_ENABLE_FFI=OFF \
      -D LLVM_ENABLE_LIBCXX=OFF \
      -D LLVM_INCLUDE_BENCHMARKS=OFF \
      -D LLVM_INCLUDE_TESTS=OFF \
      -D LLVM_INCLUDE_DOCS=OFF \
      -D LLVM_UNREACHABLE_OPTIMIZE=OFF \
      -D LLVM_ENABLE_ZSTD=OFF \
      -D LLVM_ENABLE_ZLIB=FORCE_ON \
      -D LLVM_ENABLE_ASSERTIONS=OFF \
      -D LLVM_BUILD_TELEMETRY=OFF \
      -D LLVM_ENABLE_BACKTRACES=OFF \
      -D LLVM_ENABLE_THREADS=ON \
      -D LLVM_ENABLE_EH=ON \
      -D LLVM_BUILD_DOCS=OFF \
      -D LLVM_BINUTILS_INCDIR=/usr/include \
      -D LLVM_ENABLE_PIC=OFF \
      -D LLVM_ENABLE_LTO=THIN \
      -D JOVE_STATIC_BUILD=OFF \
      -D LLVM_ENABLE_Z3_SOLVER=OFF \
      -D JOVE_USE_SYSTEM_TBB=OFF \
      -D TBB_SANITIZE=address \
      -D "LLVM_USE_SANITIZER=Address;Undefined" \
      -D LLVM_ENABLE_LTO=OFF \
      -D LLVM_USE_LINKER=lld \
      -D JOVE_HAVE_MEMFD=ON \
      -S $(pwd)/.. -B $(pwd)

fi

#     -D LLVM_ENABLE_LIBCXX=ON

ninja llvm/include/llvm/IR/Attributes.inc && ninja llvm/bin/{llvm-tblgen,llvm-dis,llvm-dlltool,llvm-cbe,opt,llc,clang,clang-tblgen,lld,jove-x86_64,jove-i386,jove-aarch64,jove-mipsel,jove-mips64el}
