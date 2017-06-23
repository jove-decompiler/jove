![Alt text](/docs/overview.png?raw=true)

# How to Build
```bash
export JOVE_SRC_DIR=/path/to/jove
git clone git@github.mit.edu:an23640/jove.git $JOVE_SRC_DIR
```
## Preparation
### Tools (Linux)
```bash
# on ArchLinux
sudo pacman -S parallel
```
### LLVM 4.0 Toolchain (Linux)
```bash
# on ArchLinux
sudo pacman -S llvm clang llvm-ocaml boost lld lldb
```
### OCamlgraph (Linux)
```bash
# on ArchLinux
yaourt -S ocaml-ocamlgraph
```
### QEMU 2.6.2 (Linux)
```bash
export QEMU_SRC_DIR=/path/to/qemu
git clone https://github.com/qemu/qemu.git -b v2.6.2 $QEMU_SRC_DIR
cd $QEMU_SRC_DIR
patch -p1 < $JOVE_SRC_DIR/patches/qemu.patch
cd -
export QEMU_BUILD_DIR=/path/to/qemu/build/directory
mkdir -p $QEMU_BUILD_DIR
cd $QEMU_BUILD_DIR
CC=clang CXX=clang++ $QEMU_SRC_DIR/configure --python=$(which python2) --target-list=aarch64-linux-user '--extra-cflags=-flto -fno-inline -fuse-ld=gold' --disable-werror --disable-gtk --disable-libnfs --disable-bzip2 --disable-numa --disable-lzo --disable-vhdx --disable-libssh2 --disable-seccomp --disable-opengl --disable-smartcard --disable-spice --disable-curses --disable-glusterfs --disable-rbd --disable-snappy --disable-tpm --disable-libusb --disable-nettle --disable-gnutls --disable-curl --disable-vnc --disable-kvm --disable-brlapi --disable-bluez --enable-tcg-interpreter --disable-fdt --disable-xfsctl --disable-pie --disable-docs --disable-vde --disable-gcrypt --disable-virglrenderer --disable-libiscsi --disable-usb-redir --disable-virtfs --disable-coroutine-pool --disable-archipelago --disable-rdma --disable-linux-aio --disable-netmap --disable-cap-ng --disable-attr --disable-vhost-net --disable-xen --disable-xen-pci-passthrough --disable-libssh2 --disable-slirp --disable-uuid --without-pixman --disable-tools --disable-system --enable-debug
make -j$(nproc)
```
## Building jove with `make(1)`
```bash
cd $JOVE_SRC_DIR
# $QEMU_SRC_DIR and $QEMU_BUILD_DIR must be set

# delete any existing build files
make clean
# must configure after cleaning
make configure
# build it!
make -j$(nproc)
```
