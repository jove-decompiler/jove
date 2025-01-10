# This implements the "wine_add_sym_files" command, usually installed
# in the debug session like
#   source ~/jove/scripts/gdb/wine_add_sym_files.py
# it is used to tell gdb where DSOs are in memory by examining WINEDEBUG output
import gdb
import os
import re

class WineAddSymFilesCommand(gdb.Command):
    def __init__(self):
        super(WineAddSymFilesCommand, self).__init__(
            "wine_add_sym_files",
            gdb.COMMAND_DATA
        )

        self._build_module_regex = None
        self._text_section_regex = None

    def _compile_regex(self, exe_name):
        """
        Compile the two necessary regex patterns based on the exe_name.
        """
        # We escape the user-supplied exe_name in case it has special regex chars
        exe_escaped = re.escape(exe_name)

        #
        # Regex #1: Identify which Windows PIDs are associated with the target exe_name:
        #
        # Example line:
        #   0024:trace:module:build_module loaded L"\\??\\Z:\\...\\mynotepad.exe" 00343200 00400000
        self._build_module_regex = re.compile(
            rf'^(?P<pid>[0-9A-Fa-f]{{4}}):.*?build_module\s+loaded\s+L"[^"]*{exe_escaped}"'
        )

        #
        # Regex #2: Identify lines that map the .text section for that same PID:
        #
        # Example line:
        #   0024:trace:module:map_image_into_view mapping /home/.../mynotepad.exe section .text at 0x463000 ...
        #
        self._text_section_regex = re.compile(
            r'^(?P<pid>[0-9A-Fa-f]{4}):.*?mapping\s+(?P<path>\S+)\s+section\s+\.text\s+at\s+(?P<addr>0x[0-9A-Fa-f]+)'
        )

    def invoke(self, arg, from_tty):
        """
        Usage:
          wine_add_sym_files [logfile] exe_name

        1) If two arguments are passed: 
             - First is the log file path
             - Second is the exe_name
        2) If only one argument is passed:
             - It's the exe_name
             - We'll read the log path from $WINEDEBUGLOG
        3) If zero or >2 arguments, we complain.
        """
        args = arg.strip().split()
        if len(args) == 0 or len(args) > 2:
            gdb.write(
                "Usage: wine_add_sym_files [log_file] exe_name\n"
                "  If log_file is omitted, $WINEDEBUGLOG is used.\n"
            )
            return

        if len(args) == 1:
            # user only passed an exe_name
            exe_name = args[0]
            debug_log_path = os.environ.get("WINEDEBUGLOG")
            if not debug_log_path:
                gdb.write("Error: No log file argument and $WINEDEBUGLOG not set.\n")
                return
        else:
            # two arguments: log_file, exe_name
            debug_log_path, exe_name = args

        # Make sure the exe_name is not empty
        exe_name = exe_name.strip()
        if not exe_name:
            gdb.write("Error: no exe_name provided.\n")
            return

        # Validate the log file exists
        if not os.path.isfile(debug_log_path):
            gdb.write(f"Error: File {debug_log_path} does not exist.\n")
            return

        # Now compile the regex with the user-provided exe_name
        self._compile_regex(exe_name)

        gdb.write(f"Reading WINEDEBUG log from: {debug_log_path}\n")
        gdb.write(f"Target executable name: {exe_name}\n")

        #
        # First pass: discover which PIDs correspond to exe_name
        #
        matched_pids = set()
        with open(debug_log_path, "r") as fh:
            for line in fh:
                build_match = self._build_module_regex.search(line)
                if build_match:
                    pid_str = build_match.group("pid")
                    matched_pids.add(pid_str.upper())

        if not matched_pids:
            gdb.write(f"Warning: No Windows PID found for {exe_name}. Skipping symbol loading.\n")
            return
        else:
            gdb.write(f"Found the following PID(s) for {exe_name}: {matched_pids}\n")

        #
        # Second pass: look for .text section lines belonging to those PIDs.
        #
        with open(debug_log_path, "r") as fh:
            for line in fh:
                match = self._text_section_regex.search(line)
                if match:
                    pid_str = match.group("pid").upper()
                    if pid_str in matched_pids:
                        dso_path = match.group("path")
                        dso_addr_str = match.group("addr")

                        # Convert from hex string ("0x463000") to int
                        try:
                            dso_addr = int(dso_addr_str, 16)
                        except ValueError:
                            gdb.write(f"Warning: could not parse address {dso_addr_str}\n")
                            continue

                        cmd = f'add-symbol-file "{dso_path}" 0x{dso_addr:x}'
                        gdb.write(f"Loading symbols for PID {pid_str}: {cmd}\n")

                        try:
                            gdb.execute(cmd, to_string=True)
                        except gdb.error as e:
                            gdb.write(f"Warning: GDB command failed for {dso_path}: {e}\n")
                            continue

        gdb.write("wine_add_sym_files: Done processing WINEDEBUG log.\n")

WineAddSymFilesCommand()

