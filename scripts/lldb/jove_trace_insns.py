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
    if not target:
        print("no target")
        return

    launch_info = target.GetLaunchInfo()
    argv = [launch_info.GetArgumentAtIndex(i) for i in list(range(launch_info.GetNumArguments()))]
    #print(argv)

    err = lldb.SBError()
    process = target.Launch(debugger.GetListener(), argv, None, None, None, None, None, 0, True, err)
    if not err.Success():
        print("Error during launch: " + str(err))
        return

    #
    # set the breakpoint that will be after all of the DSOs have been loaded
    #
    modules = target.modules

    # the two modules already in memory should be the dynamic linker and the
    # application
    modules = list(filter(lambda mod: str(mod.GetFileSpec()).find("[vdso]") == -1 and str(mod.GetFileSpec()).find("/usr/lib/ld-") == -1, modules))

    if len(modules) != 1:
        print("unable to find application module")
        return

    app_mod = modules[0]

    # now get the entry
    app_entry = app_mod.GetObjectFileEntryPointAddress()
    if not app_entry.IsValid():
        print("failed to get application module entry point")
        return

    # and set the breakpoint
    entry_bp = target.BreakpointCreateBySBAddress(app_entry)
    if not entry_bp.IsValid():
        print("Can't set a breakpoint on the module entry point")
        return

    # go
    err = process.Continue()
    if not err.Success():
        print("failed to continue")
        return

    #
    # no longer need entry breakpoint
    #
    target.BreakpointDelete(entry_bp.GetID())

    # get the thread
    thread = process.GetSelectedThread()
    if not thread:
        print("no thread")
        return

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
print('The "jove-trace-insns" command has been installed, type "help jove-trace-insns" for detailed help.')
