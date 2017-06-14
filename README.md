# How to Build
```bash
git clone git@github.mit.edu:an23640/jove.git $JOVE_SRC_DIR
```
## Preparation
### LLVM 4.0 Toolchain (Linux)
```bash
# On archlinux:
sudo pacman -S llvm clang llvm-ocaml
```
### QEMU 2.6.2 Toolchain (Linux)
```bash
# this command will download and extract QEMU sources to './qemu-2.6.2'
wget -qO- http://download.qemu-project.org/qemu-2.6.2.tar.xz
mkdir qemu-2.6.2-build
cd qemu-2.6.2-build
CC=clang CXX=clang++ ../qemu-2.6.2/configure --python=$(which python2) --target-list=arm-linux-user,i386-linux-user,x86_64-linux-user,mipsel-linux-user,aarch64-linux-user '--extra-cflags=-flto -fno-inline' --disable-gtk --disable-libnfs --disable-bzip2 --disable-numa --disable-lzo --disable-vhdx --disable-libssh2 --disable-seccomp --disable-opengl --disable-smartcard --disable-spice --disable-curses --disable-glusterfs --disable-rbd --disable-snappy --disable-tpm --disable-libusb --disable-nettle --disable-gnutls --disable-curl --disable-vnc --disable-kvm --disable-brlapi --disable-bluez --enable-tcg-interpreter --disable-fdt --disable-xfsctl --disable-pie --disable-docs --disable-vde --disable-gcrypt --disable-virglrenderer --disable-libiscsi --disable-usb-redir --disable-virtfs --disable-coroutine-pool --disable-archipelago --disable-rdma --disable-linux-aio --disable-netmap --disable-cap-ng --disable-attr --disable-vhost-net --disable-xen --disable-xen-pci-passthrough --disable-libssh2 --disable-slirp --disable-uuid --without-pixman --disable-debug-info --disable-tools --disable-system
make -j$(nproc)
```
## Building jove with `make(1)`
```bash
cd $JOVE_SRC_DIR
# delete any existing build files
make clean
# must configure after cleaning
make configure
# build it!
make -j$(nproc)
```
