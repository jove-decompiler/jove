#!/bin/false

thedir="build19"

cmds+=("pushd \"$carbc_path\" && mkdir -p $thedir && cd $thedir && retry \"$build_scripts_path/carbon-copy/build19.sh\" && popd")
