"""
This is a script to open a trace txt file from jove. Run by going
  File... -> Script File -> jove/scripts/ida/jove_trace.py
after doing so there will be a top-level menu named 'Jove'. Open trace by doing
  Jove -> Open trace...
Then you will be greeted with 2 file open dialogs, for the trace and jv

Hotkeys:
Ctrl+Shift+B - Previous block in trace
Ctrl+Shift+N - Next block in trace
Ctrl+Shift+V - Jump 1% behind current position in trace
Ctrl+Shift+M - Jump 1% ahead of current position in trace
"""

import subprocess
import ida_kernwin
import xml.etree.cElementTree as ET

ida_kernwin.create_menu("JoveToplevelMenu", "Jove", "View")

bbaddrs = []
trace = []
pos = 0

class jove_open_trace_file_t(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        global bbaddrs
        global trace
        global pos

        bbaddrs.clear()
        trace.clear()
        pos = 0

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
                prefix = "JV_0_"

                if len(line) < len(prefix) or line.find(prefix) == -1:
                    continue

                bbidx = int(line[len(prefix):])
                print("bbidx: %d" % bbidx);
                trace.append(bbidx)

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class jove_next_trace_block_t(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        global trace
        global pos

        if trace is None:
            print("jove_next_trace_block_t::activate: error: no trace file opened")
            return

        pos = min(pos + 1, len(trace) - 1)

        Addr = bbaddrs[trace[pos]]
        print("Block @ 0x%x (%d / %d)" % (Addr, pos, len(trace)));
        ida_kernwin.jumpto(Addr)

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class jove_prev_trace_block_t(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        global trace
        global pos

        if trace is None:
            print("jove_prev_trace_block_t::activate: error: no trace file opened")
            return

        pos = max(pos - 1, 0)

        Addr = bbaddrs[trace[pos]]
        print("Block @ 0x%x (%d / %d)" % (Addr, pos, len(trace)));
        ida_kernwin.jumpto(Addr)

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class jove_skip_ahead_t(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        global trace
        global pos

        if trace is None:
            print("jove_skip_ahead_t::activate: error: no trace file opened")
            return

        x = float(pos) / float(len(trace));
        x = min(x + 0.01, 1.0)
        pos = min(int(x * len(trace)), len(trace) - 1)

        Addr = bbaddrs[trace[pos]]
        print("Basic Block @ 0x%x (%d / %d)" % (Addr, pos, len(trace)));
        ida_kernwin.jumpto(Addr)

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class jove_skip_behind_t(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        global trace
        global pos

        if trace is None:
            print("jove_skip_behind_t::activate: error: no trace file opened")
            return

        x = float(pos) / float(len(trace));
        x = max(x - 0.01, 0.0)
        pos = min(int(x * len(trace)), len(trace) - 1)

        Addr = bbaddrs[trace[pos]]
        print("Block @ 0x%x (%d / %d)" % (Addr, pos, len(trace)));
        ida_kernwin.jumpto(Addr)

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

ACTION_0_NAME = "jove_action_open_trace"
ACTION_1_NAME = "jove_action_trace_next"
ACTION_2_NAME = "jove_action_trace_prev"
ACTION_3_NAME = "jove_action_skip_ahead"
ACTION_4_NAME = "jove_action_skip_behind"

ACTION_1_SHORTCUT = "Ctrl+Shift+N"
ACTION_2_SHORTCUT = "Ctrl+Shift+B"
ACTION_3_SHORTCUT = "Ctrl+Shift+M"
ACTION_4_SHORTCUT = "Ctrl+Shift+V"

desc_0 = ida_kernwin.action_desc_t(ACTION_0_NAME, "Open trace...", jove_open_trace_file_t())
desc_1 = ida_kernwin.action_desc_t(ACTION_1_NAME, "Jump to next block in trace", jove_next_trace_block_t(), ACTION_1_SHORTCUT)
desc_2 = ida_kernwin.action_desc_t(ACTION_2_NAME, "Jump to previous block in trace", jove_prev_trace_block_t(), ACTION_2_SHORTCUT)
desc_3 = ida_kernwin.action_desc_t(ACTION_3_NAME, "Skip ahead", jove_skip_ahead_t(), ACTION_3_SHORTCUT)
desc_4 = ida_kernwin.action_desc_t(ACTION_4_NAME, "Skip behind", jove_skip_behind_t(), ACTION_4_SHORTCUT)

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

if ida_kernwin.register_action(desc_3):
    ida_kernwin.attach_action_to_menu("Jove", ACTION_3_NAME, ida_kernwin.SETMENU_INS)
else:
    print("Failed to register action \"%s\"" % ACTION_3_NAME)

if ida_kernwin.register_action(desc_4):
    ida_kernwin.attach_action_to_menu("Jove", ACTION_4_NAME, ida_kernwin.SETMENU_INS)
else:
    print("Failed to register action \"%s\"" % ACTION_4_NAME)
