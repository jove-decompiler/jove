# This implements the "jove-trace" command, usually installed
# in the debug session like
#   command script import ~/jove/scripts/lldb/jove_trace.py
# this is a ptrace-replacement for tools/jove-trace.cpp (which utilizes UProbe
# tracepoints)

import optparse
import lldb
import shlex
import os
import subprocess
import fcntl
import sys
import xml.etree.cElementTree as ET

def jove_trace(debugger, command, result, dict):
    """
  TODO explain here what this thing does
    """

    command_args = shlex.split(command)
    parser = create_jove_trace_options()
    try:
        (options, args) = parser.parse_args(command_args)
    except:
        return

    jv_path = options.jv
    if not jv_path:
        print("must provide path to decompilation")
        return

    if not os.path.exists(jv_path):
        print("given path to decompilation does not exist")
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

    #
    # now all the modules are loaded in memory. at this point, parse the
    # decompilation
    #
    jv2xml_path = subprocess.Popen(["/usr/bin/which", "jv2xml"], stdout=subprocess.PIPE).communicate()[0].strip()
    xml = subprocess.Popen([jv2xml_path, jv_path], stdout=subprocess.PIPE).communicate()[0]

    tree = ET.ElementTree(ET.fromstring(xml))

    e = tree.getroot()

    l = e.findall("Decompilation")
    if len(l) != 1:
        print("error: malformed xml")
        return
    e = l[0]

    l = e.findall("Binaries")
    if len(l) != 1:
        print("error: malformed xml")
        return
    e = l[0]

    l = e.findall("item")
    if len(l) != len(target.modules):
        print("error: number of modules %d != %d doesn't match" % (len(l), len(target.modules)))
        return

    for BIdx, e in enumerate(l, 0):
        IsVDSO = int(e.findall("IsVDSO")[0].text)
        if IsVDSO == 1:
            continue

        path = e.findall("Path")[0].text
        print(path)

        mods = list(filter(lambda mod: os.path.realpath(str(mod.GetFileSpec())) == os.path.realpath(path), target.modules))
        if len(mods) != 1:
            print("could not find module for binary %s" % path)
            return

        mod = mods[0]

        icfg_e = e.findall("Analysis.ICFG")[0]
        vert_el = icfg_e.findall("vertex_property")
        for BBIdx, vert_e in enumerate(vert_el, 0):
            bb_addr = int(vert_e.findall("Addr")[0].text)
            bb_bp = target.BreakpointCreateBySBAddress(mod.ResolveFileAddress(bb_addr))
            if not bb_bp.IsValid():
                print("Can't set a breakpoint at %s+%x" % (path, bb_addr))
                return

            bb_bp_id = bb_bp.GetID()
            print("bb_bp_id=%d" % bb_bp_id)

            bb_bp.AddName("JV_%d_%d" % (BIdx, BBIdx))

    brkpt_hits = 0

    output_f = open(options.out_path, "w")
    while True:
        err = process.Continue()
        if not err.Success():
            print("failed to continue : %s" % err.GetCString())
            break

        #
        # we hit a breakpoint
        #
        brkpt_hits += 1

        t = get_stopped_thread(process, lldb.eStopReasonBreakpoint)
        if not t:
            print("failed to get stopped thread at breakpoint")
            break

        brkpt_id = t.GetStopReasonDataAtIndex(0)
        print('brk %d' % brkpt_id)
        brkpt = t.process.target.FindBreakpointByID(brkpt_id)
        name_list = lldb.SBStringList()
        brkpt.GetNames(name_list)
        if name_list.GetSize() != 1:
            print("Name list has %d items, expected 1." % (name_list.GetSize()))
        brkpt_name = name_list.GetStringAtIndex(0)
        output_f.write("%s\n" % brkpt_name)

    output_f.close()

    #
    # we're done
    #
    print("%d breakpoint hits" % brkpt_hits)
    debugger.HandleCommand("bt")

def get_stopped_threads(process, reason):
    """Returns the thread(s) with the specified stop reason in a list.

    The list can be empty if no such thread exists.
    """
    threads = []
    for t in process:
        if t.GetStopReason() == reason:
            threads.append(t)
    return threads


def get_stopped_thread(process, reason):
    """A convenience function which returns the first thread with the given stop
    reason or None.

    Example usages:

    1. Get the stopped thread due to a breakpoint condition

    ...
        from lldbutil import get_stopped_thread
        thread = get_stopped_thread(process, lldb.eStopReasonPlanComplete)
        self.assertTrue(thread.IsValid(), "There should be a thread stopped due to breakpoint condition")
    ...

    2. Get the thread stopped due to a breakpoint

    ...
        from lldbutil import get_stopped_thread
        thread = get_stopped_thread(process, lldb.eStopReasonBreakpoint)
        self.assertTrue(thread.IsValid(), "There should be a thread stopped due to breakpoint")
    ...

    """
    threads = get_stopped_threads(process, reason)
    if len(threads) == 0:
        return None
    return threads[0]

def create_jove_trace_options():
    usage = "usage: %prog"
    description = '''Trace instructions'''
    parser = optparse.OptionParser(
        description=description,
        prog='jove_trace',
        usage=usage)
    parser.add_option("-d", "--decompilation", dest="jv", help="decompilation for program to trace", metavar="decompilation.jv")
    parser.add_option("-o", "--output", dest="out_path", help="path to output trace file", metavar="trace.txt")
    return parser

lldb.debugger.HandleCommand(
    'command script add -f %s.jove_trace jove-trace' %
    __name__)
print('The "jove-trace" command has been installed, type "help jove-trace" for detailed help.')
