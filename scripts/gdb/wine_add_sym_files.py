# This implements the "wine_add_sym_files" command, usually installed
# in the debug session like
#   source ~/jove/scripts/gdb/wine_add_sym_files.py
# it is used to tell gdb where DSOs are in memory by examining WINEDEBUG output
import gdb
import os
import re
from collections import defaultdict

class WineAddSymFilesCommand(gdb.Command):
    def __init__(self):
        super(WineAddSymFilesCommand, self).__init__("wine_add_sym_files", gdb.COMMAND_DATA)
        # We'll compile our regex patterns once we know which .exe the user wants to track.
        self._build_module_regex = None
        self._all_sections_regex = None

    def _compile_regex(self, exe_name):
        """
        Compile the two necessary regex patterns based on the exe_name.
        We do two passes:

          1) Find lines with 'build_module loaded L"...exe_name..."' to identify PIDs.
          2) Find lines with 'map_image_into_view mapping <some path> section .something at 0x...'
             capturing all sections that begin with '.'.

        Note: We now allow spaces in the path by using '(?P<path>.*?)' with a lazy quantifier,
        up until the literal text ' section '.
        """
        exe_escaped = re.escape(exe_name)

        #
        # 1) Build-module lines (the loaded L"..." lines).
        #
        # Example:
        #   0024:trace:module:build_module loaded L"\\??\\C:\\Program Files\\...\\haloce.exe" ...
        #
        # We want to capture PID=0024 if the path ends with 'haloce.exe' (or user-specified exe_name).
        #
        # Notice the path can have spaces:
        #   L"\\??\\C:\\Program Files\\Microsoft Games\\Halo Custom Edition\\haloce.exe"
        #
        # So we do a lazy match, then specifically look for the user’s exe name near the end:
        self._build_module_regex = re.compile(
            rf'^'
            r'(?P<pid>[0-9A-Fa-f]{4})'         # e.g. 0024
            r':.*?'                           # skip the rest until
            r'build_module\s+loaded\s+L"'     # literal text
            r'[^"]*' + exe_escaped + r'"'     # must eventually contain 'mynotepad.exe' or 'haloce.exe', etc.
        )

        #
        # 2) All-sections lines.
        #
        # Example:
        #   0024:trace:module:map_image_into_view mapping /home/.../Program Files/... haloce.exe section .text at 0x82d000 ...
        #
        # Because the path can contain spaces, we do a lazy capture (.*?) until we see ' section '.
        #
        # Also note we capture .whatever for the section name:
        self._all_sections_regex = re.compile(
            r'^'
            r'(?P<pid>[0-9A-Fa-f]{4})'         # e.g. 0024
            r':.*?'                           # skip the rest until
            r'mapping\s+(?P<path>.*?)\s+section\s+(?P<section>\.\S+)\s+at\s+(?P<addr>0x[0-9A-Fa-f]+)'
        )

    def invoke(self, arg, from_tty):
        """
        Usage:
            wine_add_sym_files [log_file] exe_name

        1) If two arguments:
              - log_file
              - exe_name
        2) If one argument:
              - exe_name
              (log_file is read from $WINEDEBUGLOG)
        3) Otherwise, display usage.

        This will:
            - First pass: find which Windows PIDs loaded the specified exe.
            - Second pass: parse all sections for those PIDs (including spaces in file paths).
            - Then produce one add-symbol-file command per (PID, path).
        """
        args = arg.strip().split()
        if len(args) == 0 or len(args) > 2:
            gdb.write(
                "Usage: wine_add_sym_files [log_file] exe_name\n"
                "  If log_file is omitted, $WINEDEBUGLOG is used.\n"
            )
            return

        if len(args) == 1:
            exe_name = args[0]
            debug_log_path = os.environ.get("WINEDEBUGLOG")
            if not debug_log_path:
                gdb.write("Error: No log file argument and $WINEDEBUGLOG not set.\n")
                return
        else:
            debug_log_path, exe_name = args

        exe_name = exe_name.strip()
        if not exe_name:
            gdb.write("Error: no exe_name provided.\n")
            return

        if not os.path.isfile(debug_log_path):
            gdb.write(f"Error: File '{debug_log_path}' does not exist.\n")
            return

        # Compile regex with the user-specified exe_name
        self._compile_regex(exe_name)

        gdb.write(f"Reading WINEDEBUG log from: {debug_log_path}\n")
        gdb.write(f"Target executable name: {exe_name}\n")

        #
        # First pass: discover which PIDs correspond to the user-specified exe_name
        #
        matched_pids = set()
        with open(debug_log_path, "r") as fh:
            for line in fh:
                build_match = self._build_module_regex.search(line)
                if build_match:
                    pid_str = build_match.group("pid").upper()
                    matched_pids.add(pid_str)

        if not matched_pids:
            gdb.write(f"Warning: No Windows PID found for {exe_name}; no symbols loaded.\n")
            return
        else:
            gdb.write(f"Found PID(s) for {exe_name}: {matched_pids}\n")

        #
        # Second pass: gather all sections for lines that match our PIDs.
        # Store them by (pid, path) -> { section_name: address }
        #
        sections_by_pid_path = defaultdict(dict)

        with open(debug_log_path, "r") as fh:
            for line in fh:
                match = self._all_sections_regex.search(line)
                if not match:
                    continue

                pid_str  = match.group("pid").upper()
                dso_path = match.group("path").strip()
                sectname = match.group("section").strip()
                addr_str = match.group("addr").strip()

                if pid_str not in matched_pids:
                    continue
                # We only want sections that begin with '.', which the regex ensures, but let's be safe:
                if not sectname.startswith('.'):
                    continue

                try:
                    addr_val = int(addr_str, 16)
                except ValueError:
                    gdb.write(f"Warning: couldn't parse addr '{addr_str}' for {dso_path}\n")
                    continue

                key = (pid_str, dso_path)
                sections_by_pid_path[key][sectname] = addr_val

        #
        # Now issue one "add-symbol-file" per (pid, path), specifying .text as base, and -s for the others.
        #
        for (pid_str, dso_path), sect_dict in sections_by_pid_path.items():
            if ".text" not in sect_dict:
                gdb.write(f"Warning: Skipping {dso_path} (PID={pid_str}); no .text section found.\n")
                continue

            text_addr = sect_dict[".text"]
            cmd = f'add-symbol-file "{dso_path}" 0x{text_addr:x}'

            # Add -s for any other sections
            for sname, saddr in sect_dict.items():
                if sname == ".text":
                    continue
                cmd += f' -s {sname} 0x{saddr:x}'

            gdb.write(f"[PID={pid_str}] Loading symbols: {cmd}\n")
            try:
                gdb.execute(cmd, to_string=True)
            except gdb.error as e:
                gdb.write(f"Warning: GDB command failed for {dso_path}: {e}\n")
                continue

        gdb.write("wine_add_sym_files: Done processing WINEDEBUG log.\n")


# Instantiate the command so it is available in GDB
WineAddSymFilesCommand()
