# This implements the "trace-insns" command, usually installed
# in the debug session like
#   command script import ~/jove/scripts/lldb/trace_insns.py
# it is used to produce instruction traces of a thread's execution

import optparse
import lldb
import shlex
import os

def stop_reason_to_str(enum):
    """Returns the stopReason string given an enum."""
    if enum == lldb.eStopReasonInvalid:
        return "invalid"
    elif enum == lldb.eStopReasonNone:
        return "none"
    elif enum == lldb.eStopReasonTrace:
        return "trace"
    elif enum == lldb.eStopReasonBreakpoint:
        return "breakpoint"
    elif enum == lldb.eStopReasonWatchpoint:
        return "watchpoint"
    elif enum == lldb.eStopReasonExec:
        return "exec"
    elif enum == lldb.eStopReasonSignal:
        return "signal"
    elif enum == lldb.eStopReasonException:
        return "exception"
    elif enum == lldb.eStopReasonPlanComplete:
        return "plancomplete"
    elif enum == lldb.eStopReasonThreadExiting:
        return "threadexiting"
    else:
        raise Exception("Unknown StopReason enum")

def trace_insns(debugger, command, result, dict):
    """
  TODO explain here what this thing does
    """

    command_args = shlex.split(command)
    parser = create_trace_insns_options()
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

    while True:
        error = lldb.SBError()
        thread.StepInstruction(False, error)
        if error.Fail():
            print(error)
            break

        reason = thread.GetStopReason();
        #debugger.HandleCommand("target module lookup -a $pc")
        if reason != lldb.eStopReasonPlanComplete:
            print('stop reason is %s' % stop_reason_to_str(reason))
            break

        print(thread.GetFrameAtIndex(0))

def create_trace_insns_options():
    usage = "usage: %prog"
    description = '''Trace instructions'''
    parser = optparse.OptionParser(
        description=description,
        prog='trace_insns',
        usage=usage)
    return parser

lldb.debugger.HandleCommand(
    'command script add -f %s.trace_insns trace-insns' %
    __name__)
print('The "trace-insns" command has been installed, type "help trace-insns" for detailed help.')
