#!/bin/false

cmds+=("pushd \"$gperftools_path\" && mkdir -p build && cd build && retry \"$build_scripts_path/build_gperftools.sh\" && popd")
