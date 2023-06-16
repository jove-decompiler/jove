# This implements the "jove-unwind" command, usually installed
# in the debug session like
#   command script import ~/jove/scripts/lldb/jove_unwind.py
# it is used to produce meaningful backtraces of recompiled-code.

import optparse
import lldb
import shlex
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

                    completedProcess = subprocess.run(["/usr/bin/llvm-symbolizer-15", "-print-address", "-inlining=0", "-pretty-print", "-print-source-context-lines=10"], input=('%s 0x%x' % (path, addr)), capture_output=True, text=True)

                    print(completedProcess.stdout)
                    print(completedProcess.stderr)


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
print('The "jove-unwind" command has been installed, type "help jove-unwind" for detailed help.')
