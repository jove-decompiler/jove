#!/bin/bash

ssh-keygen -q -t rsa -b 4096 -N '' -f ~/.ssh/id_rsa <<<y >/dev/null 2>&1

export JOVE_TEST_UNATTENDED=1
export LLVM_SYMBOLIZER_PATH=$(which llvm-symbolizer-16)

export LANG=en_US.UTF-8

make -C /jove/tests check-linux check-win -j$(nproc)
