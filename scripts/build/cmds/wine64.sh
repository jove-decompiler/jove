#!/bin/false

cmds+=("pushd \"$wine_path\" && mkdir -p build64 && cd build64 && retry \"$build_scripts_path/wine/build64.sh\" && popd")
