"""
This is a script to open a trace txt file from jove. Run by going
  File... -> Script File -> jove/scripts/ida/jove_trace.py
after doing so there will be a top-level menu named 'Jove'. Open trace by doing
  Jove -> Open trace...
Then you will be greeted with 2 file open dialogs, for the trace and jv

Hotkeys:
Ctrl+Shift+B - Previous block in trace
Ctrl+Shift+N - Next block in trace
"""

import subprocess
import ida_kernwin
import xml.etree.cElementTree as ET

ida_kernwin.create_menu("JoveToplevelMenu", "Jove", "View")

JoveTrace = None
decompilation = None
bbaddrs = []
trace = []

class jove_open_trace_file_t(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        global decompilation 
        global bbaddrs
        global trace

        bbaddrs.clear()
        trace.clear()

        jv_fn = ida_kernwin.ask_file(0, "*.jv", "Load decompilation")
        if not jv_fn:
            return

        print("parsing decompilation %s..." % jv_fn)

        jv2xml_path = subprocess.Popen(["/usr/bin/which", "jv2xml"], stdout=subprocess.PIPE).communicate()[0].strip()
        xml = subprocess.Popen([jv2xml_path, jv_fn], stdout=subprocess.PIPE).communicate()[0]

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
        if len(l) < 3:
            print("error: malformed xml")
            return

        e = l[0]
        BIdx = 0 # the exe TODO

        path = e.findall("Path")[0].text
        print(path)

        icfg_e = e.findall("Analysis.ICFG")[0]
        vert_el = icfg_e.findall("vertex_property")
        for vert_e in vert_el:
            bbaddr = int(vert_e.findall("Addr")[0].text)
            bbaddrs.append(bbaddr)

        print("processed %d basic blocks" % len(bbaddrs))

        trace_fn = ida_kernwin.ask_file(0, "*.txt", "Load trace.txt")
        if not trace_fn:
            return

        print("opening trace file %s ..." % trace_fn)

        with open(trace_fn) as f:
            lines = f.readlines()
            for line in lines:
                print("line: \"%s\"" % line);

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class jove_next_trace_block_t(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        if JoveTrace is None:
            print("jove_next_trace_block_t::activate: error: no trace file opened")
            return
        print("Next Block Address");

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class jove_prev_trace_block_t(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        if JoveTrace is None:
            print("jove_prev_trace_block_t::activate: error: no trace file opened")
            return
        print("Previous Block Address");

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

ACTION_0_NAME = "jove_action_open_trace"
ACTION_1_NAME = "jove_action_trace_next"
ACTION_2_NAME = "jove_action_trace_prev"

ACTION_1_SHORTCUT = "Ctrl+Shift+N"
ACTION_2_SHORTCUT = "Ctrl+Shift+B"

desc_0 = ida_kernwin.action_desc_t(ACTION_0_NAME, "Open trace...", jove_open_trace_file_t())
desc_1 = ida_kernwin.action_desc_t(ACTION_1_NAME, "Jump to next block in trace", jove_next_trace_block_t(), ACTION_1_SHORTCUT)
desc_2 = ida_kernwin.action_desc_t(ACTION_2_NAME, "Jump to previous block in trace", jove_prev_trace_block_t(), ACTION_2_SHORTCUT)

if ida_kernwin.register_action(desc_0):
    ida_kernwin.attach_action_to_menu("Jove", ACTION_0_NAME, ida_kernwin.SETMENU_INS)
else:
    print("Failed to register action \"%s\"" % ACTION_0_NAME)

if ida_kernwin.register_action(desc_1):
    ida_kernwin.attach_action_to_menu("Jove", ACTION_1_NAME, ida_kernwin.SETMENU_INS)
else:
    print("Failed to register action \"%s\"" % ACTION_1_NAME)

if ida_kernwin.register_action(desc_2):
    ida_kernwin.attach_action_to_menu("Jove", ACTION_2_NAME, ida_kernwin.SETMENU_INS)
else:
    print("Failed to register action \"%s\"" % ACTION_2_NAME)
