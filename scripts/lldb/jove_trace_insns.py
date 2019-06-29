# This implements the "jove-trace-insns" command, usually installed
# in the debug session like
#   command script import ~/jove/scripts/lldb/jove_trace_insns.py
# it is used to produce meaningful instruction traces of recompiled-code.

import optparse
import lldb
import shlex
from binaryornot.check import is_binary
import os
import subprocess
import fcntl

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
                p = subprocess.Popen(["/usr/bin/llvm-symbolizer",
                "-print-address",
                "-inlining=0",
                "-pretty-print",
                "-print-source-context-lines=20"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT);

                flags = fcntl.fcntl(p.stdout, fcntl.F_GETFL) # get current p.stdout flags
                fcntl.fcntl(p.stdout, fcntl.F_SETFL, flags | os.O_NONBLOCK)

                lastAddr = 0

                while True:
                    error = lldb.SBError()
                    thread.StepInstruction(False, error)
                    if error.Fail():
                        print(error)
                        break

                    reason = thread.GetStopReason();
                    if reason == lldb.eStopReasonSignal or reason == lldb.eStopReasonThreadExiting:
                        debugger.HandleCommand("bt")
                        break

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

                    if line_addr == lastAddr:
                        continue

                    lastAddr = line_addr
                    line_path = line_path[:-len(suffix)]

                    print(frame)

                    #
                    # exec llvm-symbolizer
                    #
                    p.stdin.write('%s 0x%x\n' % (line_path, line_addr))
                    p.stdin.flush()

                    while True:
                        try:
                            print(p.stdout.read(4096))
                        except IOError as err:
                            break
                        except OSError as err:
                            break

                (stdoutdata, stderrdata) = p.communicate('\n')


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
