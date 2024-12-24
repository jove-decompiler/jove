#!/bin/bash

ssh-keygen -q -t rsa -b 4096 -N '' -f ~/.ssh/id_rsa <<<y >/dev/null 2>&1

export JOVE_TEST_UNATTENDED=1
export LLVM_SYMBOLIZER_PATH=$(which llvm-symbolizer-16)

make -C jove check -j$(nproc)
