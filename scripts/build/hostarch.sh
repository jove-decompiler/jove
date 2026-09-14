hostarch=$(dpkg --print-architecture)

case "$hostarch" in
  amd64)
    hostarch=x86_64
    ;;
  arm64)
    hostarch=aarch64
    ;;
  *)
    echo "build architecture ($hostarch) is unsupported." >&2
    exit 1
    ;;
esac
