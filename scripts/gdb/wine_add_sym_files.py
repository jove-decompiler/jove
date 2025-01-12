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
        super(WineAddSymFilesCommand, self).__init__(
            "wine_add_sym_files",
            gdb.COMMAND_DATA
        )
        #
        # We'll compile our regex patterns once we know which .exe the user
        # wants to track. See _compile_regex().
        #
        self._build_module_regex = None
        self._all_sections_regex = None

    def _compile_regex(self, exe_name):
        """
        Compile the two necessary regex patterns based on the exe_name provided by the user:
          1) Identify PIDs referencing exe_name via build_module
          2) Identify lines that map any section that begins with '.' (like .text, .data, etc.)
        """
        exe_escaped = re.escape(exe_name)

        # Regex #1: finds lines indicating that a PID loaded `exe_name`.
        # Example:
        #   0024:trace:module:build_module loaded L"...mynotepad.exe" ...
        self._build_module_regex = re.compile(
            rf'^(?P<pid>[0-9A-Fa-f]{{4}}):.*?build_module\s+loaded\s+L"[^"]*{exe_escaped}"'
        )

        # Regex #2: finds lines that mention a section that starts with '.'.
        # Example:
        #   0024:trace:module:map_image_into_view mapping /home/.../mynotepad.exe section .text at 0x463000 ...
        #
        # Captures:
        #   - pid
        #   - path (the mapped file)
        #   - section (e.g., .text, .data, .rdata, etc.)
        #   - addr (the load address in hex)
        self._all_sections_regex = re.compile(
            r'^(?P<pid>[0-9A-Fa-f]{4}):.*?mapping\s+(?P<path>\S+)\s+section\s+(?P<section>\.\S+)\s+at\s+(?P<addr>0x[0-9A-Fa-f]+)'
        )

    def invoke(self, arg, from_tty):
        """
        Usage:
          wine_add_sym_files [log_file] exe_name

        - If two arguments are provided:
            1) log_file
            2) exe_name
        - If one argument is provided:
            1) exe_name
            (the log file is read from $WINEDEBUGLOG)
        - Otherwise, we display usage and return.
        """

        args = arg.strip().split()
        if len(args) == 0 or len(args) > 2:
            gdb.write(
                "Usage: wine_add_sym_files [log_file] exe_name\n"
                "  If log_file is omitted, $WINEDEBUGLOG is used.\n"
            )
            return

        if len(args) == 1:
            # Only got an exe_name
            exe_name = args[0]
            debug_log_path = os.environ.get("WINEDEBUGLOG")
            if not debug_log_path:
                gdb.write("Error: No log file argument and $WINEDEBUGLOG not set.\n")
                return
        else:
            # Two arguments: log_file, exe_name
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
        #
        # We'll store them by (pid, path) → { section_name: address }
        #
        sections_by_pid_path = defaultdict(dict)

        with open(debug_log_path, "r") as fh:
            for line in fh:
                match = self._all_sections_regex.search(line)
                if not match:
                    continue

                pid_str  = match.group("pid").upper()
                dso_path = match.group("path")
                sectname = match.group("section").strip()
                addr_str = match.group("addr")

                # Only record sections for the PIDs we care about.
                if pid_str not in matched_pids:
                    continue

                # We only want sections that begin with '.', so quick sanity check:
                # (the regex ensures it starts with '.', but let's keep the check anyway)
                if not sectname.startswith('.'):
                    continue

                # Convert address string (e.g. "0x463000") to int
                try:
                    addr_val = int(addr_str, 16)
                except ValueError:
                    gdb.write(f"Warning: couldn't parse addr '{addr_str}' for {dso_path}\n")
                    continue

                # Store the address in our dictionary
                key = (pid_str, dso_path)
                sections_by_pid_path[key][sectname] = addr_val

        #
        # Now that we've collected all sections for each (pid, path),
        # we can issue one "add-symbol-file" command per (pid, path).
        #
        # GDB expects:
        #   add-symbol-file "PATH" TEXT_ADDR -s .data DATA_ADDR -s .bss BSS_ADDR ...
        #
        # So we must identify the `.text` address first, if it exists.
        #
        for (pid_str, dso_path), sectdict in sections_by_pid_path.items():
            if ".text" not in sectdict:
                gdb.write(f"Warning: Skipping {dso_path} (PID={pid_str}); no .text section found.\n")
                continue

            text_addr = sectdict[".text"]

            # Build the command
            # The first parameter after the file name is the .text address
            cmd = f'add-symbol-file "{dso_path}" 0x{text_addr:x}'

            # Then append -s for every other section
            for sname, saddr in sectdict.items():
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

