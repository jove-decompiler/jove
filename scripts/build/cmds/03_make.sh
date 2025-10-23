#!/bin/false

cmds+=("make -C \"$jove_path\" --output-sync utilities tcg-constants asm-offsets version -j$(nproc)")
