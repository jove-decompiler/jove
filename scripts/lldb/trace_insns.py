# This implements the "jove-trace-insns" command, usually installed
# in the debug session like
#   command script import ~/jove/scripts/lldb/trace-insns.py
# it is used to produce meaningful backtraces of recompiled-code.

import optparse
import lldb
import shlex
from binaryornot.check import is_binary
import os
import subprocess

def jove_trace_insns(debugger, command, result, dict):
    """
  TODO explain here what this thing does
    """

    command_args = shlex.split(command)
    parser = create_jove_trace_insns_options()
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
                f = open("/tmp/trace.txt", "w")
                while True:
                    cmd_result = lldb.SBCommandReturnObject()
                    debugger.GetCommandInterpreter().HandleCommand("stepi", cmd_result)
                    f.write(cmd_result.GetOutput())
                f.close()


def create_jove_trace_insns_options():
    usage = "usage: %prog"
    description = '''Print diagnostic information about a thread backtrace which will help to debug unwind problems'''
    parser = optparse.OptionParser(
        description=description,
        prog='jove_trace_insns',
        usage=usage)
    return parser

lldb.debugger.HandleCommand(
    'command script add -f %s.jove_trace_insns jove-trace-insns' %
    __name__)
print 'The "jove-trace-insns" command has been installed, type "help jove-trace-insns" for detailed help.' 
