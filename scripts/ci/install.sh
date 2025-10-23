#!/bin/bash

SCRIPT_PATH="${BASH_SOURCE[0]}"
SCRIPT_DIR="${SCRIPT_PATH%/*}"

ln -sf ${SCRIPT_DIR}/../llvm-project/build/llvm/bin/jove-x86_64   /usr/local/bin/
ln -sf ${SCRIPT_DIR}/../llvm-project/build/llvm/bin/jove-i386     /usr/local/bin/
ln -sf ${SCRIPT_DIR}/../llvm-project/build/llvm/bin/jove-aarch64  /usr/local/bin/
ln -sf ${SCRIPT_DIR}/../llvm-project/build/llvm/bin/jove-mipsel   /usr/local/bin/
ln -sf ${SCRIPT_DIR}/../llvm-project/build/llvm/bin/jove-mips64el /usr/local/bin/
