from pathlib import Path
import subprocess
import tempfile
import libtmux
import time
import os
import sys

def eprint(*args, **kwargs):
  print(*args, file=sys.stderr, **kwargs)
  sys.stderr.flush()

class JoveTester:
  ARCH_2_BITS = {
    'i386'    : 32,
    'mipsel'  : 32,
    'mips'    : 32,

    'x86_64'  : 64,
    'aarch64' : 64,
    'mips64el': 64,
  }

  PLATFORM_AND_ARCH_2PORT = {
    'linux': {
      'i386'    : 10023,
      'x86_64'  : 10024,
      'aarch64' : 10025,
      'mipsel'  : 10026,
      'mips'    : 10027,
      'mips64el': 10028,
    },
    'win': {
      'i386'   : 11023,
      'x86_64' : 11024,
      'aarch64': 11025,
    },
  }

  # debian bookworm
  REMOTE_PLATFORM_AND_ARCH_2LOADER = {
    'win': {
      'i386'   : '/usr/lib/wine/wine',
      'x86_64' : '/usr/lib/wine/wine64',
    },
  }

  TMUX_WINDOW_NAMES = [
    'qemu',
    'server',
    'ssh'
  ]

  ARCH_2_SHORT_NAME = {
      'i386'    : 'x86',
      'x86_64'  : 'x64',
      'aarch64' : 'arm64',
      'mipsel'  : 'mipsel',
      'mips'    : 'mips',
      'mips64el': 'mips64el',
  }

  def __init__(self, arch, platform, extra_server_args=[], extra_bringup_args=[], unattended=False):
    assert platform in JoveTester.PLATFORM_AND_ARCH_2PORT, "invalid platform"
    assert arch in JoveTester.PLATFORM_AND_ARCH_2PORT[platform], "invalid arch"

    self.tmux = libtmux.Server()
    self.tests_dir = Path(__file__).resolve().parent
    self.jove_dir = self.tests_dir.parent
    self.arch = arch
    self.platform = platform
    self.dsoext = "so" if platform == "linux" else "dll"
    self.variants = ["exe", "pic"] if platform == "linux" else ["EXE", "PIC"]
    self.is32 = JoveTester.ARCH_2_BITS[arch] == 32
    self.loader_args = None

    self.extra_server_args = extra_server_args
    self.extra_bringup_args = extra_bringup_args
    self.unattended = unattended

    self.guest_ssh_port = JoveTester.PLATFORM_AND_ARCH_2PORT[platform][arch]
    self.jove_server_port = self.guest_ssh_port - 5000
    self.ssh_common_args = ['-o', 'UserKnownHostsFile=/dev/null', '-o', 'StrictHostKeyChecking=no', '-o', 'LogLevel=quiet']

    self.iphost = None

    self.locate_things()

    self.vm_dir = os.getenv("JOVE_VM_" + platform.upper() + "_" + arch.upper())
    if self.vm_dir is None:
      self.td = tempfile.TemporaryDirectory()
      self.vm_dir = self.td.name
    else:
      if not os.path.isdir(self.vm_dir):
        os.mkdir(self.vm_dir)

    self.wins = [None for _ in JoveTester.TMUX_WINDOW_NAMES]
    self.create_list = []
    self.create_qemu = None
    self.create_serv = None
    self.create_ssh = None
    self.serv_process = None
    self.sess = None

  def locate_things(self):
    self.jove_bin_path     = self.jove_dir / "llvm-project" / "build" / "llvm" / "bin" / f"jove-{self.arch}"
    self.jove_client_path  = self.jove_dir / "llvm-project" / f"{self.arch}_build" / "llvm" / "bin" / f"jove-{self.arch}"
    self.jove_rt_st_path   = self.jove_dir / "bin" / self.arch / f"libjove_rt.st.{self.dsoext}"
    self.jove_rt_mt_path   = self.jove_dir / "bin" / self.arch / f"libjove_rt.mt.{self.dsoext}"
    self.bringup_path      = self.jove_dir / "mk-deb-vm" / "bringup.sh"

    assert self.jove_bin_path.is_file(),    f"missing host jove binary at {self.jove_bin_path}"
    assert self.jove_client_path.is_file(), f"missing guest jove binary at {self.jove_client_path}"
    assert self.jove_rt_st_path.is_file(),  f"missing single-threaded jove runtime at {self.jove_rt_st_path}"
    assert self.jove_rt_mt_path.is_file(),  f"missing multi-threaded jove runtime at {self.jove_rt_mt_path}"
    assert self.bringup_path.is_file(),     f"missing mk-deb-vm/bringup.sh at {self.bringup_path}"

  def session_name(self):
    return "jove_" + self.platform + "_" + self.arch

  def establish_tmux_session(self):
    tmux = self.tmux

    res = [False for _ in JoveTester.TMUX_WINDOW_NAMES]

    self.sess = None
    self.wins = [None for _ in JoveTester.TMUX_WINDOW_NAMES]

    try:
      self.sess = tmux.sessions.get(name=self.session_name())
    except libtmux._internal.query_list.ObjectDoesNotExist:
      self.sess = None

    if self.sess is None:
      self.sess = tmux.new_session(session_name=self.session_name(), window_name=JoveTester.TMUX_WINDOW_NAMES[0])
      eprint('created tmux session ' + str(self.sess))

      self.sess.set_option('history-limit', 100000)

      assert self.sess.windows[0].name == JoveTester.TMUX_WINDOW_NAMES[0]

      self.wins[0] = self.sess.windows[0]
      res[0] = True

      eprint('created tmux window ' + str(self.wins[0]))
    else:
      for win in self.sess.windows:
        try:
          self.wins[JoveTester.TMUX_WINDOW_NAMES.index(win.name)] = win
        except ValueError:
          continue

    for idx in range(0, len(self.wins)):
      if self.wins[idx] is None:
        res[idx] = True
        self.wins[idx] = self.sess.new_window(window_name=JoveTester.TMUX_WINDOW_NAMES[idx])
        eprint('created tmux window ' + str(self.wins[idx]))

    return res

  def vm_run_path(self):
    return self.vm_dir + "/run.sh"

  def exists_vm(self):
    run_path = self.vm_run_path()
    return os.path.exists(run_path) and Path(run_path).is_file()

  def create_vm(self):
    eprint("creating VM...")

    bringup_cmd = [str(self.bringup_path), '-a', self.arch, '-s', 'bookworm', '-o', self.vm_dir, '-p', str(self.guest_ssh_port)]
    if self.platform == "win":
      bringup_cmd += ["-w"]
    bringup_cmd += self.extra_bringup_args

    subprocess.run(['sudo'] + bringup_cmd, check=True)

    our_uid = os.getuid()

    chown_cmd = ["chown", "-R", "%d:%d" % (our_uid, our_uid), self.vm_dir]
    subprocess.run(['sudo'] + chown_cmd, check=True)

  def pane(self, name):
    self.establish_tmux_session()
    res = self.wins[JoveTester.TMUX_WINDOW_NAMES.index(name)].attached_pane
    res.select_pane()
    return res

  def start_vm(self):
    eprint("starting VM...")

    qp = self.pane("qemu")
    qp.send_keys("C-c", literal=False, enter=False)
    qp.send_keys('cd "%s"' % self.vm_dir)
    qp.send_keys('./run.sh')

  def start_server(self):
    eprint("starting jove server...")

    server_cmd = [str(self.jove_bin_path), 'server', '-v', '--port=%d' % self.jove_server_port]
    server_cmd += self.extra_server_args

    if self.unattended:
      self.serv_process = subprocess.Popen(server_cmd, stdin=subprocess.DEVNULL, shell=False)
    else:
      self.serv_process = None
      p = self.pane("server")
      eprint(" ".join(server_cmd))
      p.send_keys(" ".join(server_cmd)) # this is unreliable!!!

  def is_server_down(self):
    if self.serv_process is None:
      return False
    return self.serv_process.poll() != None

  def is_vm_ready(self):
    return any("login:" in row for row in self.pane("qemu").capture_pane())

  def wait_for_vm_ready(self, t=1.5):
    while not self.is_vm_ready():
      self.start_vm() # just in case

      eprint("waiting for VM...")
      time.sleep(t)
      self.pane("qemu").send_keys('')
      time.sleep(t)
      self.pane("qemu").send_keys('')
      time.sleep(t)

    eprint("VM ready.")

  def set_up_command_for_user(self, command):
    p = self.pane("ssh")
    p.send_keys("C-c", literal=False, enter=False)
    p.send_keys(" ".join(command), enter=False)

    self.sess.select_window("ssh")

  def fake_run_command_for_user(self, command):
    p = self.pane("ssh")
    p.send_keys("true || " + " ".join(command), enter=True)
    p.send_keys("", literal=False, enter=True)

  def set_up_ssh_command_for_user(self, command):
    self.set_up_command_for_user(["ssh"] + self.ssh_common_args + ['-p', str(self.guest_ssh_port), 'root@localhost'] + command)

  def fake_run_ssh_command_for_user(self, command):
    self.fake_run_command_for_user(["ssh", '-p', str(self.guest_ssh_port), 'root@localhost'] + command)

  # returns a 3-tuple (returncode, stdout, stderr)
  def ssh(self, command, check=False, text=False):
    eprint(f"ssh -p {self.guest_ssh_port} root@localhost {command}")

    assert len(command) != 0
    if len(command) == 1:
      args = ['ssh'] + self.ssh_common_args + ['-p', str(self.guest_ssh_port), 'root@localhost'] + [command[0]]
      stdin_bytes = b''
    else:
      assert len(command) >= 2
      args = ['ssh'] + self.ssh_common_args + ['-p', str(self.guest_ssh_port), 'root@localhost'] + ['xargs', '-0'] + [command[0]]

      # build NULL-terminated args
      stdin_bytes = b'\0'.join(s.encode() for s in command[1:]) + b'\0'

    try:
      ran = subprocess.run(args, check=check, input=stdin_bytes, capture_output=True, text=False, shell=False)

      sys.stdout.flush()
      sys.stderr.flush()
      sys.stdout.buffer.write(ran.stdout)
      sys.stdout.buffer.flush()
      sys.stderr.buffer.write(ran.stderr)
      sys.stderr.buffer.flush()
    except subprocess.CalledProcessError as e:
      sys.stdout.flush()
      sys.stderr.flush()
      sys.stdout.buffer.write(e.stdout)
      sys.stdout.buffer.flush()
      sys.stderr.buffer.write(e.stderr)
      sys.stderr.buffer.flush()
      raise

    if text:
      return (ran.returncode, ran.stdout.decode(), ran.stderr.decode())

    return (ran.returncode, ran.stdout, ran.stderr)

  def scp_to(self, src, dst):
    eprint(f"copying {src} to remote:{dst}")
    return subprocess.run(['scp'] + self.ssh_common_args + ['-P', str(self.guest_ssh_port), src, 'root@localhost:' + dst], check=True)

  def scp_from(self, src, dst):
    eprint(f"copying remote:{src} to {dst}")
    return subprocess.run(['scp'] + self.ssh_common_args + ['-P', str(self.guest_ssh_port), 'root@localhost:' + src, dst], check=True)

  def remote_path_exists(self, remote_path) -> bool:
    return self.ssh(['/usr/bin/stat', remote_path], check=False)[0] == 0

  def update_jove(self):
    self.scp_to(str(self.jove_client_path), '/usr/local/bin/jove')

  def update_libjove_rt(self, multi_threaded):
    rtpath = self.jove_rt_mt_path if multi_threaded else self.jove_rt_st_path
    dstdir = "/tmp" if self.platform == "win" else "/lib"
    self.scp_to(str(rtpath), f'{dstdir}/libjove_rt.{self.dsoext}')

  def inputs_for_test(self, test, platform):
    inputs_path = f"{self.tests_dir}/{platform}/inputs/{test}.inputs"

    assert os.path.exists(inputs_path), "no input for %s" % test

    return eval(open(inputs_path, 'r').read())

  def is_stderr_connection_closed_by_remote_host(self, s):
    return "Connection to localhost closed by remote host.\n" == s

  def run_tests(self, tests, multi_threaded=True, remote=True):
    mode = 'remote' if remote else 'local'
    eprint(f"running {len(tests)} {mode} tests [{self.platform} {self.arch}]...")

    if remote:
      return self.run_remote_tests(tests, multi_threaded)
    else:
      return self.run_local_tests(tests, multi_threaded)

  def run_remote_tests(self, tests, multi_threaded):
    assert self.is_remote_ready()
    self.update_libjove_rt(multi_threaded=multi_threaded)

    if self.platform == "win":
      loader = JoveTester.REMOTE_PLATFORM_AND_ARCH_2LOADER[self.platform][self.arch]
      assert self.remote_path_exists(loader) # we must find the wine loader
      self.loader_args = [loader]
    else:
      self.loader_args = []

    if self.platform == "win":
      # establish clean slate
      self.ssh([
        "rm", "-rf", "--verbose",
        f'/root/.wine{JoveTester.ARCH_2_BITS[self.arch]}',
      ], check=True)

    for test in tests:
      inputs = self.inputs_for_test(test, self.platform)

      for variant in self.variants:
        testbin_path = Path(self.tests_dir) / self.platform / "bin" / self.arch / f"{test}.{variant}"

        assert testbin_path.is_file()

        testbin = f"/tmp/{testbin_path.name}"
        self.scp_to(str(testbin_path), testbin)

        # establish clean slate
        self.ssh([
          "rm", "-rf", "--verbose",
          "/root/.jove",
          f'/root/.jv.{JoveTester.ARCH_2_SHORT_NAME[self.arch]}',
        ], check=True)

        # initialize jv
        self.ssh(["jove", "init", testbin], check=True)

        if self.platform != "win":
          # bootstrap each input
          for input_args in inputs:
            bootstrap_extra_args = ["--rtld-dbg-brk=0"] if (self.arch == "mipsel" or self.arch == "mips64el") else []
            self.ssh(["jove", "bootstrap", "--dumb-term", "--symbolize=0"] + bootstrap_extra_args + [testbin] + input_args)

        # run inputs through recompiled binary
        jove_loop_args = [
          "jove", "loop", "-v", "--dumb-term",
          f"--rtmt={int(multi_threaded)}",
          "--connect", f"{self.iphost}:{str(self.jove_server_port)}",
          "--symbolize=0"
        ]
        if self.platform == "win":
          jove_loop_args += ["--lay-out-sections"]

        # show user what we're doing
        if not self.unattended:
          self.fake_run_ssh_command_for_user(jove_loop_args + [testbin] + inputs[0])

        # for good measure, in case there is new code we run into
        for i in range(0, 2):
          for input_args in inputs:
            self.ssh(jove_loop_args + [testbin] + input_args)

        # compare result of executing testbin and recompiled testbin
        for input_args in inputs:
          if self.is_server_down():
            eprint(f"FAILURE ({self.arch} server is down!)")
            return 1

          self.ssh(["rm", "-f", "--verbose", "/tmp/stdout", "/tmp/stderr"], check=True)

          p1 = self.ssh(self.loader_args + [testbin] + input_args)
          p2 = self.ssh(
            jove_loop_args +
            [
              "--stdout=/tmp/stdout",
              "--stderr=/tmp/stderr"
            ] +
            [testbin] +
            input_args
          )

          if self.is_server_down():
            eprint(f"FAILURE ({self.arch} server is down!)")
            return 1

          stdout = tempfile.NamedTemporaryFile(delete=False)
          stdout.close()
          stderr = tempfile.NamedTemporaryFile(delete=False)
          stderr.close()

          self.scp_from("/tmp/stdout", stdout.name);
          self.scp_from("/tmp/stderr", stderr.name);

          p2_stdout = open(stdout.name, "rb").read()
          p2_stderr = open(stderr.name, "rb").read()

          os.unlink(stdout.name);
          os.unlink(stderr.name);

          return_neq = p1[0] != p2[0]
          stdout_neq = p1[1] != p2_stdout
          stderr_neq = p1[2] != p2_stderr

          failed = stdout_neq
          if self.platform != "win": # wine prints a bunch of shit to stderr
            failed = failed or return_neq
            failed = failed or stderr_neq

          if failed:
            eprint("/////////\n///////// %s REMOTE TEST FAILURE %s [%s %s]\n/////////" % \
              ("MULTI-THREADED" if multi_threaded else "SINGLE-THREADED", \
               testbin, self.platform, self.arch))
            eprint(jove_loop_args + [testbin] + input_args)

            if return_neq:
              eprint('%d != %d' % (p1[0], p2[0]))
            if stdout_neq:
              eprint('<STDOUT>\n"%s"\n\n!=\n\n"%s"\n' % (p1[1].decode(), p2_stdout.decode()))
            if stderr_neq:
              eprint('<STDERR>\n"%s"\n\n!=\n\n"%s"\n' % (p1[2].decode(), p2_stderr.decode()))

            # make it easy for user to rerun failing test
            if not self.unattended:
              self.set_up_ssh_command_for_user(jove_loop_args + [testbin] + input_args)

            return 1

    threading_name = "multi" if multi_threaded else "single"
    eprint(f"SUCCESS <remote> <{threading_name}-threaded> ({self.arch} {self.platform})")
    return 0

  def run_local_tests(self, tests, multi_threaded):
    if self.platform == "win":
      loader = self.jove_dir / "wine" / f"build{'' if self.is32 else '64'}" / "loader" / "wine"
      if not loader.exists():
        loader = Path(JoveTester.REMOTE_PLATFORM_AND_ARCH_2LOADER[self.platform][self.arch])
      assert loader.exists() # we must find the wine loader
      self.loader_args = [str(loader)]
    else:
      self.loader_args = []

    if self.platform == "win":
      self.wineprefix = os.path.expanduser(f'~/.wine{JoveTester.ARCH_2_BITS[self.arch]}')
      self.winearch = f'win{JoveTester.ARCH_2_BITS[self.arch]}'
      # establish clean slate
      subprocess.run(["rm", "-rf", "--verbose", self.wineprefix], check=True, shell=False)

    for test in tests:
      inputs = self.inputs_for_test(test, self.platform)

      for variant in self.variants:
        testbin_path = Path(self.tests_dir) / self.platform / "bin" / self.arch / f"{test}.{variant}"

        assert testbin_path.is_file()

        env = os.environ.copy()

        path_to_jv = tempfile.NamedTemporaryFile(delete=False)
        path_to_jv.close()

        eprint(f"JVPATH={path_to_jv.name}")

        os.unlink(path_to_jv.name)
        env["JVPATH"] = path_to_jv.name

        # initialize jv
        subprocess.run([f'{self.jove_bin_path}', "init", "-v", str(testbin_path)], env=env, check=True, shell=False)

        if self.platform == "win":
          env["WINEARCH"] = self.winearch
          env["WINEPREFIX"] = self.wineprefix

        with tempfile.TemporaryDirectory() as dot_jove:
          env["JOVEDIR"] = dot_jove
          eprint(f"JOVEDIR={dot_jove}")

          # prepare loop command (no --connect for local)
          jove_loop_base = [
            f'{self.jove_bin_path}', "loop", "-v", "--dumb-term",
            f'--rtmt={int(multi_threaded)}', "--symbolize=0"
          ]

          if self.platform == "win":
            jove_loop_base.insert(-1, "--lay-out-sections") # .rsrc

          # for good measure, in case there is new code we run into
          for i in range(0, 2):
            for input_args in inputs:
              subprocess.run(jove_loop_base + [str(testbin_path)] + input_args, env=env, shell=False)

          # compare result of executing testbin and recompiled testbin
          for input_args in inputs:
            stdout = tempfile.NamedTemporaryFile(delete=False)
            stdout.close()
            stderr = tempfile.NamedTemporaryFile(delete=False)
            stderr.close()

            p1 = subprocess.run(self.loader_args + [str(testbin_path)] + input_args, capture_output=True, shell=False)
            p2 = subprocess.run(jove_loop_base + [f'--stdout={stdout.name}', f'--stderr={stderr.name}'] + [str(testbin_path)] + input_args, env=env, shell=False)

            p2_stdout = open(stdout.name, "rb").read()
            p2_stderr = open(stderr.name, "rb").read()

            os.unlink(stdout.name);
            os.unlink(stderr.name);

            return_neq = p1.returncode != p2.returncode
            stdout_neq = p1.stdout != p2_stdout
            stderr_neq = p1.stderr != p2_stderr

            failed = stdout_neq
            if self.platform != "win": # wine prints a bunch of shit to stderr
              failed = failed or return_neq
              failed = failed or stderr_neq

            if failed:
              eprint("/////////\n///////// %s LOCAL TEST FAILURE %s [%s %s]\n/////////" % \
                ("MULTI-THREADED" if multi_threaded else "SINGLE-THREADED", \
                 str(testbin_path), self.platform, self.arch))
              eprint(jove_loop_base + [str(testbin_path)] + input_args)

              if return_neq:
                eprint('%d != %d' % (p1.returncode, p2.returncode))
              if stdout_neq:
                eprint('<STDOUT>\n"%s"\n\n!=\n\n"%s"\n' % (p1.stdout.decode(), p2_stdout.decode()))
              if stderr_neq:
                eprint('<STDERR>\n"%s"\n\n!=\n\n"%s"\n' % (p1.stderr.decode(), p2_stderr.decode()))

              os.unlink(path_to_jv.name)
              return 1

        os.unlink(path_to_jv.name)

    threading_name = "multi" if multi_threaded else "single"
    eprint(f"SUCCESS <local> <{threading_name}-threaded> ({self.arch} {self.platform})")
    return 0


  def is_remote_ready(self):
    return not (self.iphost is None)

  def get_remote_ready(self, update_jove=True):
    self.create_list = self.establish_tmux_session()
    self.create_qemu, self.create_serv, self.create_ssh = tuple(self.create_list)

    if self.create_qemu:
      if not self.exists_vm():
        self.create_vm()
      self.start_vm()
    else:
      if not self.exists_vm():
        self.create_vm()
        self.start_vm()

    # blocks until VM is booted.
    self.wait_for_vm_ready()

    #
    # get IP of host seen by guest
    #
    self.iphost = self.ssh(['ip', 'route', 'show'], text=True, check=True)[1].strip().split()[2]
    eprint("iphost: %s" % self.iphost)

    if update_jove:
      self.update_jove()

    #
    # start jove server
    #
    if self.unattended or self.create_serv:
      self.start_server()
      time.sleep(1.0) # ?? we are seeing apparently weird poll() behavior

  def __del__(self):
    eprint(f"tester: cleaning up... [{self.platform} {self.arch}]")
    if self.unattended:
      if self.is_remote_ready():
        self.ssh(['systemctl', 'poweroff'])
        time.sleep(3)

      if self.serv_process is not None:
        try:
          self.serv_process.terminate()  # Gracefully terminate
          self.serv_process.wait(timeout=5)  # Wait for the process to exit
        except Exception as e:
          self.serv_process.kill()  # Forcefully kill if it doesn't exit
          eprint(f"Forced server subprocess termination: {e}")

      if self.sess is not None:
        self.sess.kill_session()
