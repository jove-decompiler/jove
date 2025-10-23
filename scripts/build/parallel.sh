#!/bin/false

printf "%s\0" "${cmds[@]}" \
  | parallel -0 -j "$PARALLEL_JOBS" -v --lb --halt soon,fail=1
cmds=()
