#!/bin/bash

ssh-keygen -q -t rsa -b 4096 -N '' -f ~/.ssh/id_rsa <<<y >/dev/null 2>&1

make -C jove check -j$(nproc)
