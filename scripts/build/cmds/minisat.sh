#!/bin/false

cmds+=("pushd \"$minisat_path\" && mkdir -p build && cd build && retry \"$build_scripts_path/minisat/build.sh\" && popd")
