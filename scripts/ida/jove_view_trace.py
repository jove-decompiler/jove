"""
This is a script to open a trace txt file from jove. Run by going
  File... -> Script File -> /path/to/jove/scripts/ida/jove_trace.py
after doing so there will be a top-level menu named 'Jove'. Open trace by doing
  Jove -> Open trace...

Hotkeys:
Ctrl+Shift+B - Previous block in trace
Ctrl+Shift+N - Next block in trace
Ctrl+Shift+V - Jump 1% behind current position in trace
Ctrl+Shift+M - Jump 1% ahead of current position in trace
Ctrl+Shift+F - Jump to the next basic block in the trace that is a return
"""

import subprocess
import ida_kernwin
import xml.etree.cElementTree as ET

ida_kernwin.create_menu("JoveToplevelMenu", "Jove", "View")

trace_filename = None
decompilation = None
bbvec = []
trace = []
pos = 0

class jove_open_trace_file_t(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        global trace_filename
        global trace
        global pos

        trace_fn = ida_kernwin.ask_file(0, "*.txt", "Load trace.txt")
        if not trace_fn:
            return

        #
        # reset global state
        #
        trace.clear()
        pos = 0
        trace_filename = trace_fn

        print("opening trace file %s..." % trace_fn)
        with open(trace_fn) as f:
            for line in f:
                prefix = "JV_0_"

                if len(line) <= len(prefix) or line.find(prefix) != 0:
                    print("unrecognized line in trace file: \"%s\"; assuming EOF" % line)
                    return

                bbidx = int(line[len(prefix):])
                trace.append(bbidx)

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class jove_next_trace_block_t(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        global trace_filename
        global trace
        global bbvec
        global pos

        if len(trace) == 0 or not trace_filename:
            print("[jove] no trace file opened?")
            return

        pos = min(pos + 1, len(trace) - 1)

        Addr = bbvec[trace[pos]][0]
        print("Block %d @ 0x%x (%d / %d) in %s" % (trace[pos], Addr, pos + 1, len(trace), trace_filename));
        ida_kernwin.jumpto(Addr)

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class jove_prev_trace_block_t(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        global trace_filename
        global trace
        global bbvec
        global pos

        if len(trace) == 0 or not trace_filename:
            print("[jove] no trace file opened?")
            return

        pos = max(pos - 1, 0)

        Addr = bbvec[trace[pos]][0]
        print("Block %d @ 0x%x (%d / %d) in %s" % (trace[pos], Addr, pos + 1, len(trace), trace_filename));
        ida_kernwin.jumpto(Addr)

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class jove_skip_ahead_t(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        global trace_filename
        global trace
        global bbvec
        global pos

        if len(trace) == 0 or not trace_filename:
            print("[jove] no trace file opened?")
            return

        x = float(pos) / float(len(trace));
        x = min(x + 0.01, 1.0)
        pos = min(int(x * len(trace)), len(trace) - 1)

        Addr = bbvec[trace[pos]][0]
        print("Block %d @ 0x%x (%d / %d) in %s" % (trace[pos], Addr, pos + 1, len(trace), trace_filename));
        ida_kernwin.jumpto(Addr)

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class jove_skip_behind_t(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        global trace_filename
        global trace
        global bbvec
        global pos

        if len(trace) == 0 or not trace_filename:
            print("[jove] no trace file opened?")
            return

        x = float(pos) / float(len(trace));
        x = max(x - 0.01, 0.0)
        pos = min(int(x * len(trace)), len(trace) - 1)

        Addr = bbvec[trace[pos]][0]
        print("Block %d @ 0x%x (%d / %d) in %s" % (trace[pos], Addr, pos + 1, len(trace), trace_filename));
        ida_kernwin.jumpto(Addr)

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

class jove_skip_to_ret_t(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        global trace_filename
        global trace
        global bbvec
        global pos

        if len(trace) == 0 or not trace_filename:
            print("[jove] no trace file opened?")
            return

        assert(pos >= 0 and pos < len(trace))
        while True:
            pos += 1
            if pos == len(trace):
                pos = len(trace) - 1
                print("[jove] end of trace")
                return

            bbaddr = bbvec[trace[pos]][0]
            termty = bbvec[trace[pos]][1]
            if termty == 6:
                print("Found Return Block %d @ 0x%x (%d / %d) in %s" % (trace[pos], bbaddr, pos + 1, len(trace), trace_filename));
                ida_kernwin.jumpto(bbaddr)
                return

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS

jv_fn = ida_kernwin.ask_file(0, "*.jv", "Load decompilation")
if not jv_fn:
    pass
else:
    print("parsing decompilation...")

    jv2xml_path = subprocess.Popen(["/usr/bin/which", "jv2xml"], stdout=subprocess.PIPE).communicate()[0].strip()
    xml = subprocess.Popen([jv2xml_path, jv_fn], stdout=subprocess.PIPE).communicate()[0]

    decompilation = ET.ElementTree(ET.fromstring(xml))

    #
    # build bbvec
    #
    if not decompilation:
        print("couldn't open decompilation")
    else:
        e = decompilation.getroot()

        l = e.findall("Decompilation")
        assert(len(l) == 1);
        e = l[0]

        l = e.findall("Binaries")
        assert(len(l) == 1);
        e = l[0]

        l = e.findall("item")
        assert(len(l) >= 3);

        BIdx = 0 # just the exe
        e = l[BIdx]

        binpath = e.findall("Path")[0].text
        print("processing basic blocks in %s" % binpath)

        icfg_e = e.findall("Analysis.ICFG")[0]
        vert_el = icfg_e.findall("vertex_property")
        for vert_e in vert_el:
            bbaddr = int(vert_e.findall("Addr")[0].text)
            termty = int(vert_e.findall("Term.Type")[0].text)
            bbvec.append((bbaddr, termty))

        actions_variants = [
          ("jove_action_open_trace",  "Open trace...",                   "",             jove_open_trace_file_t()),
          ("jove_action_trace_next",  "Jump to next block in trace",     "Ctrl+Shift+N", jove_next_trace_block_t()),
          ("jove_action_trace_prev",  "Jump to previous block in trace", "Ctrl+Shift+B", jove_prev_trace_block_t()),
          ("jove_action_skip_ahead",  "Skip ahead",                      "Ctrl+Shift+M", jove_skip_ahead_t()),
          ("jove_action_skip_behind", "Skip behind",                     "Ctrl+Shift+V", jove_skip_behind_t()),
          ("jove_action_skip_to_ret", "Skip to return",                  "Ctrl+Shift+F", jove_skip_to_ret_t()),
        ]

        for action_name, label, shortcut, obj in actions_variants:
            desc = ida_kernwin.action_desc_t(action_name, label, obj, shortcut)
            if ida_kernwin.register_action(desc):
                ida_kernwin.attach_action_to_menu("Jove", action_name, ida_kernwin.SETMENU_INS)
            else:
                print("Failed to register action \"%s\"" % action_name)
