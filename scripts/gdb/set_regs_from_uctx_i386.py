import gdb

class SetRegistersFromUContext(gdb.Command):
    "Set CPU registers from a ucontext_t structure in a signal handler."

    def __init__(self):
        super(SetRegistersFromUContext, self).__init__("set-registers-from-uctx", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        # Ensure the argument is provided
        if not arg:
            gdb.write("Usage: set-registers-from-uctx <uctx_ptr>\n", gdb.STDERR)
            return

        # Evaluate the ucontext_t pointer
        try:
            uctx_ptr = gdb.parse_and_eval(arg)
        except gdb.error as e:
            gdb.write(f"Failed to evaluate uctx pointer: {e}\n", gdb.STDERR)
            return

        # Dereference the ucontext_t pointer
        try:
            uctx = uctx_ptr.dereference()
        except gdb.error as e:
            gdb.write(f"Failed to dereference uctx pointer: {e}\n", gdb.STDERR)
            return

        # Access general registers (gregs)
        try:
            gregs = uctx["uc_mcontext"]["gregs"]
        except gdb.error as e:
            gdb.write(f"Failed to access general registers: {e}\n", gdb.STDERR)
            return

        # Map of i386 registers and their indices in gregs
        reg_map = {
            "gs": 0,
            "fs": 1,
            "es": 2,
            "ds": 3,
            "edi": 4,
            "esi": 5,
            "ebp": 6,
            "esp": 7,
            "ebx": 8,
            "edx": 9,
            "ecx": 10,
            "eax": 11,
            "trapno": 12,
            "err": 13,
            "eip": 14,
            "cs": 15,
            "eflags": 16,
            "uesp": 17,
            "ss": 18
        }

        # Set each register
        for reg, idx in reg_map.items():
            try:
                gdb.execute(f"set ${reg} = {gregs[idx]}")
            except gdb.error as e:
                gdb.write(f"Failed to set {reg}: {e}\n", gdb.STDERR)

        gdb.write("Registers set from ucontext_t.\n")

# Register the command
SetRegistersFromUContext()
