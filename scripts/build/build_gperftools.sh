#!/bin/bash
set -e
set -o pipefail
set -x

build_scripts_path=$(cd "$(dirname -- "$0")"; pwd)

OPTIND=1

frame_pointer=

function usage() {
  echo "usage: $0 [-F]"
  echo "    -F: build with frame pointers"
}

while getopts "F" opt; do
  case "$opt" in
    F)
      frame_pointer=1
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

cmake_args=(
  -G Ninja
  -D CMAKE_BUILD_TYPE=RelWithDebInfo
  -D "CMAKE_C_COMPILER=$(command -v clang)"
  -D "CMAKE_CXX_COMPILER=$(command -v clang++)"
  -D BUILD_SHARED_LIBS=OFF
  -D BUILD_TESTING=OFF
  -D GPERFTOOLS_BUILD_HEAP_PROFILER=OFF
  -D GPERFTOOLS_BUILD_CPU_PROFILER=OFF
  -D gperftools_enable_libunwind=OFF
  -D gperftools_build_benchmark=OFF
)

if [ -n "$frame_pointer" ]; then
  cmake_args+=(
    -D gperftools_enable_frame_pointers=ON
  )
fi

if [ ! -f build.ninja ]; then
  cmake "${cmake_args[@]}" -S "$(pwd)/.." -B "$(pwd)"
fi

ninja
