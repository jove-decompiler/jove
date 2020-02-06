# This implements the "jove_unwind" command, usually installed
# in the debug session like
#   source ~/jove/scripts/gdb/trace_insns.py
# it is used to produce meaningful backtraces of recompiled-code.

import gdb
import subprocess

crashed = False

def signal_stop_handler (event):
    global crashed
    print("signal_stop_handler")
    if (isinstance (event, gdb.StopEvent)):
        print ("event type: stop")
    if (isinstance (event, gdb.SignalEvent)):
        print ("stop reason: signal")
        print ("stop signal: %s" % (event.stop_signal))
        if event.stop_signal == "SIGSEGV":
            crashed = True
        if (event.inferior_thread is not None):
            print ("thread num: %s" % (event.inferior_thread.num))

class TraceInstructionsCommand(gdb.Command):
    def __init__(self):
        super(TraceInstructionsCommand, self).__init__("trace_insns", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        global crashed

        gdb.events.stop.connect(signal_stop_handler)

        while not crashed:
            #print(("crashed=%d (1)" % crashed))
            s=gdb.execute("stepi", True, True)
            #print(("crashed=%d (2)" % crashed))
            #print(("s=\"%s\"" % s))

TraceInstructionsCommand()
