# This implements the "jove-trace-insns" command, usually installed
# in the debug session like
#   command script import ~/jove/scripts/lldb/trace_insns.py
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
                while True:
                    error = lldb.SBError()
                    thread.StepInstruction(False, error)
                    if error.Fail():
                        print(error)
                        return

                    reason = thread.GetStopReason();
                    if reason == lldb.eStopReasonSignal or reason == lldb.eStopReasonThreadExiting:
                        debugger.HandleCommand("bt")
                        return

                    frame = thread.GetFrameAtIndex(0)
                    line_entry = frame.GetLineEntry()
                    line_path = str(line_entry.GetFileSpec())

                    suffix = ".fake"
                    if not line_path.endswith(suffix):
                        continue

                    # check for non-zero line number
                    line_addr = line_entry.GetLine()
                    if line_addr == 0:
                        continue

                    print(frame)


def create_jove_trace_insns_options():
    usage = "usage: %prog"
    description = '''Trace instructions'''
    parser = optparse.OptionParser(
        description=description,
        prog='jove_trace_insns',
        usage=usage)
    return parser

lldb.debugger.HandleCommand(
    'command script add -f %s.jove_trace_insns jove-trace-insns' %
    __name__)
print 'The "jove-trace-insns" command has been installed, type "help jove-trace-insns" for detailed help.' 
