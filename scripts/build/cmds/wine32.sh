#!/bin/false

thedir="build"

cmds+=("pushd \"$wine_path\" && mkdir -p $thedir && cd $thedir && retry \"$build_scripts_path/wine/build.sh\" && popd")
