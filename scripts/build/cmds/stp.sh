#!/bin/false

cmds+=("pushd \"$stp_path\" && mkdir -p build && cd build && retry \"$build_scripts_path/stp/build.sh\" && popd")
