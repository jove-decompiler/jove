#!/bin/false

cmds+=("pushd \"$wine_path\" && mkdir -p build && cd build && retry \"$build_scripts_path/wine/build.sh\" && popd")
