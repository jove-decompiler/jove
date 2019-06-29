# This implements the "jove-unwind" command, usually installed
# in the debug session like
#   command script import ~/jove/scripts/lldb/unwind.py
# it is used to produce meaningful backtraces of recompiled-code.

import optparse
import lldb
import shlex
from binaryornot.check import is_binary
import os
import subprocess

def jove_unwind(debugger, command, result, dict):
    """
  TODO explain here what this thing does
    """

    command_args = shlex.split(command)
    parser = create_jove_unwind_options()
    try:
        (options, args) = parser.parse_args(command_args)
    except:
        return
    target = debugger.GetSelectedTarget()
    if target:
        process = target.GetProcess()
        if process:
            thread = process.GetSelectedThread()
            if thread:
                for frame in thread.frames:
                    line_entry = frame.GetLineEntry()

                    path = str(line_entry.GetFileSpec())
                    addr = line_entry.GetLine()

                    suffix = ".fake"
                    if not path.endswith(suffix):
                        continue

                    path = path[:-len(suffix)]

                    #print('path=%s' % path)
                    #print('addr=0x%x' % addr)

                    #
                    # exec llvm-symbolizer
                    #
                    p = subprocess.Popen(["/usr/bin/llvm-symbolizer", "-print-source-context-lines=10"], stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE);
                    (stdoutdata, stderrdata) = p.communicate('%s 0x%x' % (path, addr))

                    print stdoutdata
                    print stderrdata


def create_jove_unwind_options():
    usage = "usage: %prog"
    description = '''Print diagnostic information about a thread backtrace which will help to debug unwind problems'''
    parser = optparse.OptionParser(
        description=description,
        prog='jove_unwind',
        usage=usage)
    return parser

lldb.debugger.HandleCommand(
    'command script add -f %s.jove_unwind jove-unwind' %
    __name__)
print 'The "jove-unwind" command has been installed, type "help jove-unwind" for detailed help.'
