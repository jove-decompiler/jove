# This implements the "jove_trace" command, usually installed
# in the debug session like
#   source ~/jove/scripts/gdb/jove_trace.py
# this is a ptrace-replacement for tools/jove-trace

import optparse
import gdb
import os
import re
import subprocess
import xml.etree.cElementTree as ET

output_file = None
decompilation = None
seen_bin_list = []
brkpoints = []

class JoveTraceBreakpoint(gdb.Breakpoint):
    def __init__(self, BIdx, BBIdx, Addr):
        gdb.Breakpoint.__init__ (self, spec=("*0x%x" % (Addr)), internal=1)
        self.silent = True
        self.count = 0
        self.BIdx = BIdx
        self.BBIdx = BBIdx

    def stop(self):
        global output_file
        if not output_file:
            print("[ERROR] JoveTraceBreakpoint::stop: not output_file")
            return True
        self.count += 1
        output_file.write("JV_%d_%d\n" % (self.BIdx, self.BBIdx))
        output_file.flush()
        return False

def on_loaded_binary (loaded_path, start, end, offset):
    global decompilation
    global seen_bin_list
    global brkpoints

    #
    # see if any binary's path is a substring of the given path (because it is
    # probably running in a chroot)
    #
    e = decompilation.getroot()

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

    for BIdx, e in enumerate(l, 0):
        if BIdx in seen_bin_list:
            continue

        IsVDSO = int(e.findall("IsVDSO")[0].text)
        if IsVDSO == 1:
            continue

        IsRTLD = int(e.findall("IsDynamicLinker")[0].text)
        if IsRTLD == 1:
            continue

        path = e.findall("Path")[0].text
        if path in loaded_path:
            seen_bin_list += [BIdx]

            print("%s @ [0x%x, 0x%x) off=0x%x" % (path, start, end, offset))

            #
            # place breakpoints
            #
            icfg_e = e.findall("Analysis.ICFG")[0]
            vert_el = icfg_e.findall("vertex_property")
            for BBIdx, vert_e in enumerate(vert_el, 0):
                bb_addr = int(vert_e.findall("Addr")[0].text)
                brkpoints.append(JoveTraceBreakpoint(BIdx, BBIdx, start - offset + bb_addr))

def scan_for_binaries ():
    t = gdb.selected_thread()
    if not t:
        print("[ERROR] scan_for_binaries: no selected thread")
        return

    pid = t.ptid[0]

    #
    # parse virtual memory mappings of process
    #
    try:
        maps_file = open("/proc/%d/maps" % (pid), 'r')
    except:
        print("[ERROR] scan_for_binaries: couldn't open /proc/%d/maps" % (pid))
        raise

    for line in maps_file.readlines():  # for each mapped region
        m = re.match(r'([0-9A-Fa-f]+)-([0-9A-Fa-f]+) ([-r])([-w])([-x])([-p]) ([0-9A-Fa-f]+) ', line)
        if m.group(5) == 'x':  # is executable region?
            start = int(m.group(1), 16)
            end = int(m.group(2), 16)
            offset = int(m.group(7), 16)
            part = line.partition('/') # XXX this is a bit sloppy
            if part[1] == '/': # is this a file?
                path = "/" + part[2].strip()
                on_loaded_binary (path, start, end, offset)

    maps_file.close()

def signal_stop_handler (event):
    if (isinstance (event, gdb.SignalEvent)):
        print ("stop reason: signal")
        print ("stop signal: %s" % (event.stop_signal))
        #if event.stop_signal == "SIGSEGV":
        #    crashed = True
        if (event.inferior_thread is not None):
            print ("thread num: %s" % (event.inferior_thread.num))

def breakpoint_stop_handler (event):
    if (isinstance (event, gdb.BreakpointEvent)):
        print ("stop reason: breakpoint")
        print ("first breakpoint number: %s" % (event.breakpoint.number))
        for bp in event.breakpoints:
        	print ("breakpoint number: %s" % (bp.number))
        if ( event.inferior_thread is not None) :
            print ("thread num: %s" % (event.inferior_thread.num))
        else:
            print ("all threads stopped")

def new_objfile_handler (event):
    assert (isinstance (event, gdb.NewObjFileEvent))
    print ("new objfile name: %s" % (event.new_objfile.filename))
    scan_for_binaries()

    #print ("event type: new_objfile")
    #for objf in gdb.current_progspace().objfiles():
    #    print(objf.filename)

def clear_objfiles_handler (event):
    assert (isinstance (event, gdb.ClearObjFilesEvent))
    print ("event type: clear_objfiles")
    print ("progspace: %s" % (event.progspace.filename))

def exit_handler (event):
    global output_file

    #
    # clean up after ourselves
    #
    assert (isinstance (event, gdb.ExitedEvent))
    print ("jove_trace: ExitedEvent")

    try:
        gdb.events.new_objfile.disconnect (new_objfile_handler)
    except:
        pass

    try:
        gdb.events.clear_objfiles.disconnect (clear_objfiles_handler)
    except:
        pass

    try:
        gdb.events.exited.disconnect (exit_handler)
    except:
        pass

    if output_file:
        output_file.close()

    output_file = None

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

class JoveTraceCommand(gdb.Command):
    def __init__(self):
        super(JoveTraceCommand, self).__init__("jove_trace", gdb.COMMAND_RUNNING)

    def invoke(self, argument, from_tty):
        global decompilation
        global seen_bin_list
        global output_file
        global brkpoints
        """
        TODO explain here what this thing does
        """
        command_args = gdb.string_to_argv(argument)
        parser = create_jove_trace_options()
        try:
            (options, args) = parser.parse_args(command_args)
        except:
            return

        jv_path = options.jv
        if not jv_path:
            print("must provide path to decompilation (-d)")
            return

        if not os.path.exists(jv_path):
            print("given path to decompilation %s does not exist" % (jv_path))
            return

        output_path = options.out_path
        if not output_path:
            print("did not specify output path with (-o)")
            return

        assert (not output_file)
        try:
            output_file = open(options.out_path, "w")
        except:
            print("failed to open output at %s" % (output_path))
            raise

        print("parsing decompilation...")
        jv2xml_path = subprocess.Popen(["/usr/bin/which", "jv2xml"], stdout=subprocess.PIPE).communicate()[0].strip()
        if not os.path.exists(jv2xml_path):
            print("can't find jv2xml at %s" % (jv2xml_path))
            return

        xml = subprocess.Popen([jv2xml_path, jv_path], stdout=subprocess.PIPE).communicate()[0]

        decompilation = ET.ElementTree(ET.fromstring(xml))

        e = decompilation.getroot()

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
        print("%d binaries" % (len(l)))

        for BIdx, e in enumerate(l, 0):
            icfg_e = e.findall("Analysis.ICFG")[0]
            vert_el = icfg_e.findall("vertex_property")

            path = e.findall("Path")[0].text
            print("%s (%d basic blocks)" % (path, len(vert_el)))

        #
        # this is the point of no return
        #
        seen_bin_list.clear()
        brkpoints.clear()

        gdb.events.new_objfile.connect (new_objfile_handler)
        gdb.events.clear_objfiles.connect (clear_objfiles_handler)
        gdb.events.exited.connect (exit_handler)

        gdb.execute("run", True, False)

        #gdb.events.stop.connect (signal_stop_handler)
        #gdb.events.stop.connect (breakpoint_stop_handler)

        #while not crashed:
            #print(("crashed=%d (1)" % crashed))
            #s=gdb.execute("stepi", True, True)
            #print(("crashed=%d (2)" % crashed))
            #print(("s=\"%s\"" % s))

JoveTraceCommand()
