#!/usr/bin/python3

# If you need to produce meaningful backtraces of recompiled-code and your gdb
# does not have python support, this script can be used as a fallback. simply
# copy and paste the full output of 'bt' into a text file and supply it to this
# script, along with another short text file that defines a python dictionary
# mapping shortened library names to full absolute paths. Example of such files:
#
# bt.txt:
#
# #0  J67b90 () at libc.so.6.fake:425012
# #1  0x000000fff4839a6c in _jove_call (...)
# #2  0x000000fff48a27f8 in j11d500 () at libc.so.6.fake:1169852
# #3  0x000000fff48a5950 in j11dc38 () at libc.so.6.fake:1170568
# #4  0x000000fff4a1aab0 in J11dd50 () at libc.so.6.fake:1170804
# #5  0x000000aaaaacd8bc in _jove_call (...)
# #6  0x000000aaaaafc4e8 in J79d0 () at ls.fake:31528
# #7  0x000000fff4839a6c in _jove_call (...)
# #8  0x000000fff4b4b428 in j4af10 () at libc.so.6.fake:307068
# #9  0x000000fff4b4a534 in J4afe0 () at libc.so.6.fake:307364
# #10 0x000000aaaaacd8bc in _jove_call (...)
# #11 0x000000aaaaad4588 in j99dc () at ls.fake:39452
# #12 0x000000aaaaad449c in J99d0 () at ls.fake:39384
# #13 0x000000aaaaad405c in _jove_call_entry () at ls.fake:7
# #14 0x000000aaaaad3fe4 in _jove_begin (a0=<optimized out>, a1=<optimized out>, v0=<optimized out>, sp_addr=<optimized out>) at lib/arch/mips64el/jove.c:186
# #15 0x000000aaaaac64a8 in _jove_start ()
#
# dso_names.txt:
#
# {'libc.so.6': '/usr/lib/mips64el-linux-gnuabi64/libc.so.6',
#  'ls': '/usr/bin/ls'}
#

import subprocess
import sys

if len(sys.argv) != 3:
  print("usage: jove_unwind.py bt.txt dso_names.txt")
  sys.exit(1)

dso_full_names_fp = sys.argv[2]
dso_names_map = eval(open(dso_full_names_fp, 'r').read())

fp = sys.argv[1]

with open(fp) as f:
    lines = [line.rstrip() for line in f]

for l in lines:
  pos = l.find(".fake")
  if pos == -1:
    continue

  sp_pos = l.rfind(' ', 0, pos)
  if sp_pos == -1:
    continue

  s = l[sp_pos+1:]
  col_pos = s.find(":")
  if col_pos == -1:
    continue
  off = int(s[col_pos+1:])

  nm = s[:col_pos]
  assert(nm.endswith(".fake"))
  nm = nm[0:-len(".fake")]

  dso = dso_names_map[nm]

  #print("%s @ 0x%x" % (dso, off))

  use_addr2line = False

  if not use_addr2line:
      completedProcess = subprocess.run(\
          ["/usr/bin/llvm-symbolizer-13",\
          "--print-address",\
          "--output-style=GNU",\
          "--pretty-print"],\
          input=('%s 0x%x' % (dso, off)),\
          capture_output=True, text=True)
  else:
      completedProcess = subprocess.run(\
          ["/usr/bin/addr2line", "-e", dso],\
          input=('0x%x' % (off)),\
          capture_output=True, text=True)

  if completedProcess.stdout.strip():
      print(completedProcess.stdout.strip())

  if completedProcess.stderr.strip():
      print(completedProcess.stderr.strip())

sys.exit(0)
