#!/bin/false

thedir="build19"

cmds+=("pushd \"$llknife_path\" && mkdir -p $thedir && cd $thedir && retry \"$build_scripts_path/llknife/build19.sh\" && popd")
