# Getting started
## Tested environments
- Debian 11 (i386, x86_64, mipsel, mips64el)
- Arch Linux (x86_64)
- Arch Linux 32 (i386)
- ArchLinuxARM (arm64)
## Prerequisites
- `gcc` (capable of building LLVM)
- `ninja`
- `cmake`
- `python`
- `libxml2`
- `z3`
- `python` `yaml` module
## Optional
- `easy-graph` ([debian](https://packages.debian.org/testing/libgraph-easy-perl), [AUR](https://aur.archlinux.org/packages/perl-graph-easy/))
## Building llvm
```bash
cd jove/
git submodule update --init --recursive
make -C third_party/ build-llvm
```
## Building jove
```bash
cd jove/
make
```
# Examples
## `ls` (coreutils)
```bash
cd jove/bin

jove-init -o $HOME/.jove/ls -git /usr/bin/ls
jove-bootstrap -d $HOME/.jove/ls /usr/bin/ls -q -- -la /
sudo jove-loop -d $HOME/.jove/ls --sysroot ls.sysroot /usr/bin/ls -- -la /
```
Tip: On debian systems run the following to install debug symbols
```bash
for f in $(jove-dump $HOME/.jove/ls --list-binaries) ; do find-dbgsym-packages $f ; done
```
After installing `easy-graph`, try this
```bash
for f in $(jove-dump --list-functions=libc $HOME/.jove/ls) ; do echo $f ; jove-cfg -d $HOME/.jove/dnsmasq -b libc $f ; sleep 10s ; done
```
