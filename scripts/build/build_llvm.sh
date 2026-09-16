#!/bin/bash
set -e
set -o pipefail
set -x

OPTIND=1

cross=
arch=
target=
tblgen=
frame_pointer=
assertions="OFF"
asan=
tsan=

function usage() {
  echo "usage: $0 [-T] -a architecture [-t target] [-C] [-A] [-F] [-S sanitizer]"
  echo "    -a architecture: build on specified architecture (aarch64, i386, mips64el, mipsel, or x86_64)"
  echo "    -T:              only build llvm-tblgen"
  echo "    -C:              this build is doing cross-compilation"
  echo "    -A:              build with assertions"
  echo "    -F:              build with frame pointers"
  echo "    -S:              build with specified sanitizer (address or thread)"
  echo "    -h:              Show this help."
}

while getopts ":a:t:TFCS:Ah" opt; do
  case "$opt" in
    a)
      arch=$OPTARG
      ;;
    t)
      target=$OPTARG
    ;;
    T)
      tblgen=1
      ;;
    F)
      frame_pointer=1
      ;;
    C)
      cross=1
      ;;
    A)
      assertions="ON"
      ;;
    S)
      if [ "$OPTARG" = "address" ]; then
        asan=1
      elif [ "$OPTARG" = "thread" ]; then
        tsan=1
      else
        echo "Unknown sanitizer ($OPTARG); must be address or thread" >&2
        exit 1
      fi
      ;;
    h)
      usage
      exit 0
      ;;
    :)
      echo "Option -$OPTARG requires an argument." >&2
      usage >&2
      exit 1
      ;;
    \?)
      echo "Unknown option: -$OPTARG" >&2
      usage >&2
      exit 1
      ;;
  esac
done

shift $((OPTIND - 1))

if [ -z "$arch" ]; then
  echo "An architecture is required." >&2
  usage >&2
  exit 1
fi

# if target not explicitly specified then assumed to identical to architecture of build.
if [ -z "$target" ]; then
  target=$arch
fi

triple=
system_processor=
llvm_target_arch=
llvm_targets=
jove_targets=
threads=
optimization="-O3"
lto="OFF"
skip_rpath="FALSE"
enable_ffi="OFF"
have_memfd="ON"
cmake_args=(
  -G Ninja
  -D CMAKE_BUILD_TYPE=RelWithDebInfo
  -D "CMAKE_C_COMPILER=$(command -v clang-19)"
  -D "CMAKE_CXX_COMPILER=$(command -v clang++-19)"
  -D LLVM_BUILD_TESTS=OFF
  -D LLVM_INCLUDE_TESTS=OFF
  -D LLVM_ENABLE_RTTI=ON
  -D LLVM_ENABLE_LIBXML2=OFF
  -D LLVM_ENABLE_TERMINFO=OFF
  -D LLVM_ENABLE_LIBCXX=OFF
  -D LLVM_INCLUDE_BENCHMARKS=OFF
  -D LLVM_INCLUDE_DOCS=OFF
  -D LLVM_UNREACHABLE_OPTIMIZE=OFF
  -D LLVM_ENABLE_Z3_SOLVER=OFF
  -D LLVM_ENABLE_ZSTD=OFF
  -D LLVM_ENABLE_ZLIB=FORCE_ON
  -D LLVM_ENABLE_BINDINGS=OFF
  -D LLVM_BUILD_TELEMETRY=OFF
  -D LLVM_ENABLE_BACKTRACES=OFF
  -D LLVM_ENABLE_EH=ON
  -D LLVM_BUILD_DOCS=OFF
  -D LLVM_BINUTILS_INCDIR=/usr/include
  -D LLVM_USE_LINKER=lld
  -D LLVM_DISABLE_ASSEMBLY_FILES=ON
)

if [ -n "$asan" ]; then
 cmake_args+=(
   -D LLVM_ENABLE_PIC=ON
   -D TBB_SANITIZE=address
   -D "LLVM_USE_SANITIZER=Address;Undefined"
 )
elif [ -n "$tsan" ]; then
 cmake_args+=(
   -D LLVM_ENABLE_PIC=ON
   -D TBB_SANITIZE=thread
   -D "LLVM_USE_SANITIZER=Thread"
   -D JOVE_SANITIZE_THREAD=ON
 )
else
 cmake_args+=(
   -D LLVM_ENABLE_PIC=OFF
   -D JOVE_STATIC_BUILD=ON
 )
fi

case "$arch" in
  aarch64)
    triple="aarch64-linux-gnu"
    system_processor="aarch64"
    llvm_target_arch="aarch64"
    threads="ON"
    lto="THIN"
    skip_rpath="TRUE"
    ;;

  i386)
    triple="i686-linux-gnu"
    system_processor="i386"
    llvm_target_arch="i386"
    threads="ON"
    lto="THIN"

    cmake_args+=(-D "LLVM_BUILD_32_BITS=ON")
    ;;

  mips64el)
    triple="mips64el-linux-gnuabi64"
    system_processor="mips64el"
    llvm_target_arch="mips64el"
    threads="OFF"
    lto="OFF"
    enable_ffi="ON"
    ;;

  mipsel)
    triple="mipsel-linux-gnu"
    optimization="-Oz"
    system_processor="mips"
    llvm_target_arch="mipsel"
    threads="OFF"
    lto="THIN"
    enable_ffi="ON"
    ;;

  x86_64)
    triple="x86_64-linux-gnu"
    system_processor="x86_64"
    llvm_target_arch="x86_64"
    threads="ON"
    lto="THIN"
    ;;

  *)
    echo "Unsupported architecture: $arch" >&2
    usage >&2
    exit 1
    ;;
esac

case "$target" in
  aarch64)
    llvm_targets="AArch64"
    jove_targets="aarch64"
    ;;

  i386)
    llvm_targets="X86"
    jove_targets="i386"
    ;;

  mips64el)
    llvm_targets="Mips"
    jove_targets="mips64el"
    ;;

  mipsel)
    llvm_targets="Mips"
    jove_targets="mipsel"
    ;;

  x86_64)
    llvm_targets="X86"
    jove_targets="x86_64"
    ;;

  all)
    llvm_targets="Mips;X86;AArch64"
    jove_targets="i386;x86_64;mipsel;mips64el;aarch64"
    ;;

  *)
    echo "Unrecognized target: $arch" >&2
    usage >&2
    exit 1
    ;;
esac

if [ -n "$cross" ]; then
  projects="llvm"
else
  projects="clang;lld;llvm"
fi

cmake_args+=(
  -D "LLVM_ENABLE_PROJECTS=$projects"
  -D "LLVM_TARGETS_TO_BUILD=$llvm_targets"
  -D "JOVE_TARGETS_TO_BUILD=$jove_targets"
  -D "CMAKE_SKIP_RPATH=$skip_rpath"
  -D "LLVM_ENABLE_LTO=$lto"
  -D "LLVM_ENABLE_ASSERTIONS=$assertions"
  -D "LLVM_ENABLE_THREADS=$threads"
  -D "LLVM_ENABLE_FFI=$enable_ffi"
  -D "JOVE_HAVE_MEMFD=$have_memfd"
)

if [ -n "$cross" ]; then
  cmake_args+=(
    -D CMAKE_SYSTEM_NAME=Linux
    -D CMAKE_CROSSCOMPILING=True
    -D "CMAKE_SYSTEM_PROCESSOR=$system_processor"
    -D "LLVM_TARGET_ARCH=$llvm_target_arch"
    -D "LLVM_DEFAULT_TARGET_TRIPLE=$triple"
    -D "LLVM_HOST_TRIPLE=$triple"
    -D "LLVM_NATIVE_TOOL_DIR=$(pwd)/../build/llvm/bin"
#   -D "LLVM_TABLEGEN=$(pwd)/../tblgen_build/llvm/bin/llvm-tblgen"
  )
fi

ourcflags=(
  "--target=$triple"
  "$optimization"
)

# better debugging
if [ -n "$frame_pointer" ]; then
  ourcflags+=(
    -fno-omit-frame-pointer
    -mno-omit-leaf-frame-pointer
  )
fi

# faster debugging
ourcflags+=(
  -g1
  -ggdb
  -gz=none
)

# seems to help with stack traces under WINE
ourcflags+=(-gdwarf-4)

cmake_args+=(
  -D "CMAKE_C_FLAGS_RELWITHDEBINFO=${ourcflags[*]}"
  -D "CMAKE_CXX_FLAGS_RELWITHDEBINFO=${ourcflags[*]}"
)

if [ ! -f build.ninja ]; then
  cmake "${cmake_args[@]}" -S "$(pwd)/.." -B "$(pwd)"
fi

if [ -n "$tblgen" ]; then
  ninja llvm/include/llvm/IR/Attributes.inc
  ninja llvm/bin/llvm-tblgen
  exit 0
fi

IFS=';' read -r -a the_targets <<< "$jove_targets"

ninja_targets=()

if [ -z "$cross" ]; then
  ninja_targets=(
    llvm/bin/clang
    llvm/bin/clang-tblgen
    llvm/bin/llc
    llvm/bin/lld
    llvm/bin/llvm-as
    llvm/bin/llvm-cbe
    llvm/bin/llvm-config
    llvm/bin/llvm-dis
    llvm/bin/llvm-dlltool
    llvm/bin/llvm-link
    llvm/bin/llvm-tblgen
    llvm/bin/opt
    llvm/lib/libLLVMMCJIT.a # for KLEE
  )
fi

for the_target in "${the_targets[@]}"; do
  ninja_targets+=("llvm/bin/jove-$the_target")
done

ninja llvm/include/llvm/IR/Attributes.inc
ninja "${ninja_targets[@]}"
