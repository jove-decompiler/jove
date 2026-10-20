#!/bin/sh

. /etc/os-release

case $ID in
  debian|ubuntu)
    hostarch=$(dpkg --print-architecture)
    ;;
  gentoo)
    hostarch=$(portageq envvar ARCH) || exit 1
    ;;
  *)
    printf 'Unsupported distribution: %s\n' "$ID" >&2
    exit 1
    ;;
esac

case $hostarch in
  amd64) hostarch=x86_64 ;;
  arm64) hostarch=aarch64 ;;
  *)
    printf 'Unsupported build architecture.\n' >&2
    exit 1
    ;;
esac

echo $hostarch
