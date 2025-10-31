#!/bin/false

cmds+=("retry \"make -C '$jove_path' --output-sync all-helpers-mk env-inits softfpu -j$(nproc)\"")
