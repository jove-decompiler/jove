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

jove-bootstrap -d $HOME/.jove/ls /usr/bin/ls -q -- --version
jove-bootstrap -d $HOME/.jove/ls /usr/bin/ls -q -- --help
jove-bootstrap -d $HOME/.jove/ls /usr/bin/ls -q -- -la /

sudo jove-loop -d $HOME/.jove/ls --sysroot ls.recompiled /usr/bin/ls -- -la /
```
