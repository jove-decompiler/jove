#!/bin/false

thedir="build16"

cmds+=("pushd \"$llknife_path\" && mkdir -p $thedir && cd $thedir && retry \"$build_scripts_path/llknife/build16.sh\" && popd")
