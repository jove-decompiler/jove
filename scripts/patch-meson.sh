#!/usr/bin/bash

mapfile -t files < <(find /usr/lib -type f -name clike.py -print)

if ((${#files[@]} == 0)); then
  echo "Error: clike.py not found" >&2
  exit 1
elif ((${#files[@]} > 1)); then
  printf 'Error: multiple clike.py files found:\n' >&2
  printf '  %s\n' "${files[@]}" >&2
  exit 1
fi

patch "${files[0]}" <<'PATCH'
--- a
+++ b
@@ -75,9 +75,16 @@
         # TODO: this could probably be added to the DynamicLinker instead
         if isinstance(self.compiler.linker, (GnuLikeDynamicLinkerMixin, SolarisDynamicLinker, CompCertDynamicLinker)):
             group_start = -1
             group_end = -1
+            ignore = False
             for i, each in enumerate(new):
+                if ignore:
+                    ignore = False
+                    continue
+                if each == "-Xclang":
+                    ignore = True
+                    continue
                 if not GROUP_FLAGS.search(each):
                     continue
                 group_end = i
                 if group_start < 0:
PATCH
