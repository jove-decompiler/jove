# Getting started
## Tested environments
- Arch Linux (x86_64)
- Arch Linux 32 (i386)
- Arch Linux ARM (arm64)
- Debian 11 (mips64el)
## Prerequisites
- `gcc`,`g++`
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
jove-init -o $HOME/.jove/ls -git $(which ls)
jove-dyn -d $HOME/.jove/ls $(which ls) -q -args=--version
jove-dyn -d $HOME/.jove/ls $(which ls) -q -args=--help
jove-dyn -d $HOME/.jove/ls $(which ls) -q -args=/
((j=0)) ; while jove-recompile -d $HOME/.jove/ls -o ls.recompiled.$j ; do sudo jove-run ls.recompiled.$j $(which ls) / ; sudo chown -R aeden:aeden $HOME/.jove/ls ; ((j++)) ; echo j is $j ; done
```
