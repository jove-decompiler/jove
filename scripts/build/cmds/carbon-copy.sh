#!/bin/false

cmds+=("pushd \"$carbc_path\" && mkdir -p build19 && cd build19 && retry \"$build_scripts_path/carbon-copy/build19.sh\" && popd")
