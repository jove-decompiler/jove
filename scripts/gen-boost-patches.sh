#!/bin/bash
scripts_path=$(cd "$(dirname -- "$0")"; pwd)

set -euo pipefail

# Where to write the patch files
PATCH_DIR="${scripts_path}/../patches"
mkdir -p "$PATCH_DIR"

# Ensure we're in a git repo (superproject)
git rev-parse --is-inside-work-tree >/dev/null

# Find dirty submodules under libs/, then emit one patch file per lib
mapfile -t DIRTY_LIBS < <(
  git submodule foreach -q '
    # Print the path of the submodule if it has any local changes
    if test -n "$(git status --porcelain)"; then
      echo "$path"
    fi
  ' | grep -E '^libs/'
)

if ((${#DIRTY_LIBS[@]} == 0)); then
  echo "No modified Boost libraries found."
  exit 0
fi

for libpath in "${DIRTY_LIBS[@]}"; do
  libname="$(basename "$libpath")"
  outfile="${PATCH_DIR}/boost-${libname}.diff"
  echo "Generating ${outfile} …"

  pushd "$libpath" >/dev/null
  # Diff with 20 lines of context for the whole submodule worktree
  git diff -U20 . > "$outfile"
  popd >/dev/null

  # If somehow the diff is empty, remove the empty file
  if [[ ! -s "$outfile" ]]; then
    rm -f "$outfile"
    echo "  (no changes; removed empty ${outfile})"
  fi
done

echo "Done. Patches (if any) are in: ${PATCH_DIR}"
