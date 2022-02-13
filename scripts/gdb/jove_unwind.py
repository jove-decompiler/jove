# This implements the "jove_unwind" command, usually installed
# in the debug session like
#   source ~/jove/scripts/gdb/jove_unwind.py
# it is used to produce meaningful backtraces of recompiled-code.

import gdb
import subprocess

class JoveUnwindCommand(gdb.Command):
    def __init__(self):
        super(JoveUnwindCommand, self).__init__("jove_unwind", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        inferiors = gdb.inferiors()
        for inferior in inferiors:
            print("inferior " + str(inferior))
            for thread in inferior.threads():
                # Change to our threads context
                thread.switch()

                print("thread " + str(thread))

                # Take a human readable copy of the backtrace, we'll need this for display later.
                #o = gdb.execute('bt', to_string=True)

                gdb.newest_frame()
                cur_frame = gdb.selected_frame()
                while cur_frame is not None:
                    suffix = ".fake"
                    sal = cur_frame.find_sal()
                    st = sal.symtab
                    if st is not None and st.fullname().endswith(suffix):
                        path = st.fullname()
                        path = path[:-len(suffix)]

                        #print(path)

                        use_addr2line = False

                        if not use_addr2line:
                            completedProcess = subprocess.run(\
                                ["/usr/bin/llvm-symbolizer-13",\
                                "--print-address",\
                                "--output-style=GNU",\
                                "--pretty-print"],\
                                input=('%s 0x%x' % (path, sal.line)),\
                                capture_output=True, text=True)
                        else:
                            completedProcess = subprocess.run(\
                                ["/usr/bin/addr2line", "-e", path],\
                                input=('0x%x' % (sal.line)),\
                                capture_output=True, text=True)

                        if completedProcess.stdout.strip():
                            print(completedProcess.stdout.strip())

                        if completedProcess.stderr.strip():
                            print(completedProcess.stderr.strip())

                    cur_frame = cur_frame.older()

JoveUnwindCommand()
