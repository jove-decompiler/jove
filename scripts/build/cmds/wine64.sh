#!/bin/false

thedir="build64"

cmds+=("pushd \"$wine_path\" && mkdir -p $thedir && cd $thedir && retry \"$build_scripts_path/wine/build64.sh\" && popd")
