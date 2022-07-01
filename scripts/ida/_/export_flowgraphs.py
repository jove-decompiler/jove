import os
import idc
import sys
import time
import idaapi

f = open(idc.ARGV[1], 'w') if len(idc.ARGV) > 1 else sys.stderr
log = f.write

if len(idc.ARGV) != 3:
    log("Usage: export_function_flowgraphs.py log_file.txt output_directory\n")
    time.sleep(15)
    idc.qexit(1)

output_dir = idc.ARGV[2]

log("output directory: %s\n" % output_dir)

idc.auto_wait()

# clear names
for FIdx in range(ida_funcs.get_func_qty()):
    func = ida_funcs.getn_func(FIdx)
    idaapi.set_name(func.start_ea, "")

for FIdx in range(ida_funcs.get_func_qty()):
    func = ida_funcs.getn_func(FIdx)

    output_fp = output_dir + "/" + hex(func.start_ea) + ".gdl"
    #log("output file path: %s\n" % output_fp)

    ida_gdl.gen_flow_graph(output_fp, hex(func.start_ea), func, ida_idaapi.BADADDR, ida_idaapi.BADADDR, ida_gdl.CHART_PRINT_NAMES | ida_gdl.CHART_GEN_GDL)

log("export_function_flowgraphs.py finished executing.\n")

idc.qexit(0)
