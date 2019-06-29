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
                        break

                    reason = thread.GetStopReason();
                    #print('stop reason is %s' % stop_reason_to_str(reason))
                    #debugger.HandleCommand("target module lookup -a $pc")
                    if reason != lldb.eStopReasonPlanComplete:
                        break

                    frame = thread.GetFrameAtIndex(0)
                    print(frame)

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
print 'The "trace-insns" command has been installed, type "help trace-insns" for detailed help.' 
