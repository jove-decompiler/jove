#!/bin/bash
set -e
set -o pipefail
set -x

# Reset in case getopts has been used previously in the shell.
OPTIND=1

usage()
{
  echo "usage: $0 [-c | -s] -a architecture [-t target] [-S sanitizer] [-w]"
  echo "    -a architecture: build on specified architecture (aarch64, i386, mips64el, mipsel, or x86_64)"
  echo "    -C:              this build is doing cross-compilation"
  echo "    -c               Build carbon (jove helpers + LTO)."
  echo "    -s               Build softfpu (jove helpers + LTO, using clang 16)."
  echo "    -F:              build with frame pointers"
  echo "    -t target        QEMU target (if not specified then assumed to be arch)."
  echo "    -w               Enable Windows-specific configuration, currently a no-op."
  echo "    -S sanitizer:    use specified sanitizer (address or thread)"
  echo "    -D               for debugging"
  echo "    -h               Show this help."
}

cross=
arch=
carbon=
softfpu=
target=
win=
asan=
tsan=
frame_pointer=
debug=

while getopts ":a:t:csS:CDFwh" opt; do
  case $opt in
    a)
      arch=$OPTARG
    ;;
    c)
      carbon="carbon"
    ;;
    s)
      softfpu="softfpu"
    ;;
    t)
      target=$OPTARG
    ;;
    C)
      cross=1
      ;;
    F)
      frame_pointer=1
      ;;
    D)
      debug=1
      ;;
    w)
      win="win"
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
      usage >&2
      exit 0
    ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      usage >&2
      exit 1
    ;;
    :)
      echo "Option -$OPTARG requires an argument." >&2
      usage >&2
      exit 1
    ;;
  esac
done

if [ -z "$arch" ]; then
  echo "Option -a is required." >&2
  usage >&2
  exit 1
fi

if [ -n "$carbon" ] && [ -n "$softfpu" ]; then
  echo "Options -c and -s are mutually exclusive." >&2
  usage >&2
  exit 1
fi

ourldflags=(-fuse-ld=lld)

if [ "$target" = "all" ]; then
  targetlist="x86_64-linux-user,i386-linux-user,aarch64-linux-user,mipsel-linux-user,mips64el-linux-user"
else
  # if target not explicitly specified then assumed to be identical to build's architecture.
  if [ -z "$target" ]; then
    target=$arch
  fi
  targetlist="$target-linux-user"
fi


CLANGVER=19
configure_args=()
ourcflags=()

# better debugging
if [ -n "$frame_pointer" ]; then
  ourcflags+=(
    -fno-omit-frame-pointer
    -mno-omit-leaf-frame-pointer
  )
fi

# faster debugging
ourcflags+=(
  -g
  -ggdb
  -gz=none
)

# seems to help with stack traces under WINE
ourcflags+=(-gdwarf-4)

extraconf=(--enable-jove)
buildlist=()

if [ -n "$carbon" ]; then
  extraconf=(--enable-jove-helpers --enable-lto)

  buildlist+=("qemu-$target" "qemu-$target.bitcode")
elif [ -n "$softfpu" ]; then
  extraconf=(--enable-jove-helpers --enable-lto)
  CLANGVER=16

  buildlist+=(
    "qemu-$target"
    "qemu-$target.bitcode"
    "libfpu_soft-$target-linux-user.a"
  )
else
  if [ "$arch" = mips64el ]; then
    # mips64/qemu needs LTO even for the normal jove library build.
    extraconf+=(--enable-lto)
  fi

  if [ "$target" = "all" ]; then
    buildlist+=(
      "libqemu4jove-x86_64.a"
      "libqemu4jove-i386.a"
      "libqemu4jove-aarch64.a"
      "libqemu4jove-mipsel.a"
      "libqemu4jove-mips64el.a"
    )
  else
    buildlist+=("libqemu4jove-$target.a")
  fi
fi

if [ -n "$win" ]; then
  : # extraconf+=(--enable-ms-bitfields)
fi

if [ -n "$asan" ]; then
  configure_args+=(
    --enable-pie
    --enable-asan
    --enable-ubsan
  )
  ourldflags+=(-pie)
elif [ -n "$tsan" ]; then
  configure_args+=(
    --enable-pie
    --enable-tsan
  )
  ourldflags+=(-pie)
else
  configure_args+=(
    --disable-pie
  )
  ourldflags+=(-no-pie)
fi

the_cc=clang-$CLANGVER
the_cxx=clang++-$CLANGVER
the_ar=llvm-ar-$CLANGVER
the_ranlib=llvm-ranlib-$CLANGVER
the_ld=ld.lld-$CLANGVER

if [ -n "$cross" ]; then
  case "$arch" in
    aarch64)
      triple=aarch64-linux-gnu
      cross_prefix=aarch64-linux-gnu-
      cpu=aarch64
      ;;

    i386)
      triple=i686-linux-gnu
      cross_prefix=i686-linux-gnu-
      cpu=i386
      ourldflags+=(-latomic)
      ;;

    mips64el)
      triple=mips64el-linux-gnuabi64
      cross_prefix=mips64el-linux-gnuabi64-
      cpu=mips
      ;;

    mipsel)
      triple=mipsel-linux-gnu
      cross_prefix=mipsel-linux-gnu-
      cpu=mips
      ;;

    x86_64)
      triple=x86_64-linux-gnu
      cross_prefix=x86_64-linux-gnu-
      cpu=x86_64
      ;;

    *)
      echo "Unknown architecture: $arch" >&2
      usage >&2
      exit 1
      ;;
  esac

  ourcflags+=("--target=$triple")
  configure_args+=(
    "--cross-prefix=$cross_prefix"
    "--cpu=$cpu"
  )
fi

configure_args+=(
  "--target-list=$targetlist"
  "--cc=$the_cc"
  "--host-cc=$the_cc"
  "--cxx=$the_cxx"
  "--objcc=$the_cc"
  --disable-werror
  --extra-ldflags="${ourldflags[*]}"
  --enable-tcg-interpreter
  --enable-tcg
  --disable-plugins
  --disable-tools
  --disable-docs
  --disable-install-blobs
  --disable-qom-cast-debug
  --disable-vhost-kernel
  --disable-vhost-net
  --disable-vhost-user
  --disable-vhost-user-blk-server
  --disable-vhost-crypto
  --disable-vhost-vdpa
  --disable-stack-protector
  --disable-capstone
  --disable-libdw
  --disable-tpm
  --disable-keyring
  --disable-passt
  --disable-selinux
  --disable-libssh
  --disable-linux-io-uring
  --disable-sdl
  --disable-vnc
  --disable-xen
  --disable-zstd
  --enable-trace-backends=nop
  --disable-malloc-trim
)

if [ -n "$debug" ]; then
  configure_args+=(
    --enable-debug-tcg
  )
fi

configure_args+=(
  --extra-cflags="${ourcflags[*]}"
  "${extraconf[@]}"
)

case "$arch" in
  aarch64)
    pkg_config_libdir=/usr/lib/aarch64-linux-gnu/pkgconfig
    ;;
  mips64el)
    pkg_config_libdir=/usr/lib/mips64el-linux-gnuabi64/pkgconfig
    ;;
  mipsel)
    pkg_config_libdir=/usr/lib/mipsel-linux-gnu/pkgconfig
    ;;
  i386)
    pkg_config_libdir=/usr/lib/i386-linux-gnu/pkgconfig
    ;;
  x86_64)
    pkg_config_libdir=/usr/lib/x86_64-linux-gnu/pkgconfig
    ;;
esac

export PKG_CONFIG_LIBDIR="$pkg_config_libdir:/usr/share/pkgconfig"

if [ ! -f build.ninja ]; then
  env AR="$the_ar" RANLIB="$the_ranlib" LD="$the_ld" \
      PKG_CONFIG_LIBDIR=$pkg_config_libdir \
  ../configure "${configure_args[@]}"
fi

ninja "${buildlist[@]}"
