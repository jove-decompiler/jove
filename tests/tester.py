from pathlib import Path
import subprocess
import tempfile
import libtmux
import time
import os

class JoveTester:
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

  PLATFORM_AND_ARCH_2RUN = {
    'win': {
      'i386'   : ['/usr/lib/wine/wine'],
      'x86_64' : ['/usr/lib/wine/wine64'],
    },
  }

  WINDOWS = [
    'qemu',
    'server',
    'ssh'
  ]

  def __init__(self, tests_dir, arch, platform, extra_server_args=[], extra_bringup_args=[], unattended=False):
    assert platform in JoveTester.PLATFORM_AND_ARCH_2PORT, "invalid platform"
    assert arch in JoveTester.PLATFORM_AND_ARCH_2PORT[platform], "invalid arch"

    self.tmux = libtmux.Server()
    self.tests_dir = tests_dir
    self.arch = arch
    self.platform = platform
    self.dsoext = "so" if platform == "linux" else "dll"
    self.variants = ["exe", "pic"] if platform == "linux" else ["EXE", "PIC"]
    self.run = []
    if platform in JoveTester.PLATFORM_AND_ARCH_2RUN:
      self.run = JoveTester.PLATFORM_AND_ARCH_2RUN[platform][arch]

    self.extra_server_args = extra_server_args
    self.extra_bringup_args = extra_bringup_args
    self.unattended = unattended

    self.guest_ssh_port = JoveTester.PLATFORM_AND_ARCH_2PORT[platform][arch]
    self.jove_server_port = self.guest_ssh_port - 5000
    self.ssh_common_args = ['-o', 'UserKnownHostsFile=/dev/null', '-o', 'StrictHostKeyChecking=no', '-o', 'LogLevel=quiet']

    self.iphost = None

    self.find_things()

    self.vm_dir = os.getenv("JOVE_VM_" + platform.upper() + "_" + arch.upper())
    if self.vm_dir is None:
      self.td = tempfile.TemporaryDirectory()
      self.vm_dir = self.td.name
    else:
      if not os.path.isdir(self.vm_dir):
        os.mkdir(self.vm_dir)

    self.wins = [None for _ in JoveTester.WINDOWS]
    self.create_list = []
    self.create_qemu = None
    self.create_serv = None
    self.create_ssh = None
    self.serv_process = None

  def find_things(self):
    self.jove_server_path = '%s/../llvm-project/build/llvm/bin/jove-%s' % (self.tests_dir, self.arch)
    assert Path(self.jove_server_path).is_file(), "missing host jove binary"

    self.jove_client_path = '%s/../llvm-project/%s_build/llvm/bin/jove-%s' % (self.tests_dir, self.arch, self.arch)
    assert Path(self.jove_client_path).is_file(), "missing guest jove binary"

    self.jove_rt_st_path = '%s/../bin/%s/libjove_rt.st.%s' % (self.tests_dir, self.arch, self.dsoext)
    assert Path(self.jove_rt_st_path).is_file(), "missing single-threaded jove runtime"

    self.jove_rt_mt_path = '%s/../bin/%s/libjove_rt.mt.%s' % (self.tests_dir, self.arch, self.dsoext)
    assert Path(self.jove_rt_mt_path).is_file(), "missing multi-threaded jove runtime"

    self.bringup_path = '%s/../mk-deb-vm/bringup.sh' % self.tests_dir
    assert Path(self.bringup_path).is_file(), "missing mk-deb-vm/bringup.sh"

  def session_name(self):
    return "jove_" + self.platform + "_" + self.arch

  def establish_tmux_session(self):
    tmux = self.tmux

    res = [False for _ in JoveTester.WINDOWS]

    self.sess = None
    self.wins = [None for _ in JoveTester.WINDOWS]

    try:
      self.sess = tmux.sessions.get(name=self.session_name())
    except libtmux._internal.query_list.ObjectDoesNotExist:
      self.sess = None

    if self.sess is None:
      self.sess = tmux.new_session(session_name=self.session_name(), window_name=JoveTester.WINDOWS[0])
      print('created tmux session ' + str(self.sess))

      assert self.sess.windows[0].name == JoveTester.WINDOWS[0]

      self.wins[0] = self.sess.windows[0]
      res[0] = True

      print('created tmux window ' + str(self.wins[0]))
    else:
      for win in self.sess.windows:
        try:
          self.wins[JoveTester.WINDOWS.index(win.name)] = win
        except ValueError:
          continue

    for idx in range(0, len(self.wins)):
      if self.wins[idx] is None:
        res[idx] = True
        self.wins[idx] = self.sess.new_window(window_name=JoveTester.WINDOWS[idx])
        print('created tmux window ' + str(self.wins[idx]))

    return res

  def vm_run_path(self):
    return self.vm_dir + "/run.sh"

  def exists_vm(self):
    run_path = self.vm_run_path()
    return os.path.exists(run_path) and Path(run_path).is_file()

  def create_vm(self):
    print("creating VM...")

    bringup_cmd = [self.bringup_path, '-a', self.arch, '-s', 'bookworm', '-o', self.vm_dir, '-p', str(self.guest_ssh_port)]
    if self.platform == "win":
      bringup_cmd += ["-w"]
    bringup_cmd += self.extra_bringup_args

    subprocess.run(['sudo'] + bringup_cmd, check=True)

    our_uid = os.getuid()

    chown_cmd = ["chown", "-R", "%d:%d" % (our_uid, our_uid), self.vm_dir]
    subprocess.run(['sudo'] + chown_cmd, check=True)

  def pane(self, name):
    self.establish_tmux_session()
    res = self.wins[JoveTester.WINDOWS.index(name)].attached_pane
    res.select_pane()
    return res

  def start_vm(self):
    print("starting VM...")

    qp = self.pane("qemu")
    qp.send_keys("C-c", literal=False, enter=False)
    qp.send_keys('cd "%s"' % self.vm_dir)
    qp.send_keys('./run.sh')

  def start_server(self):
    print("starting jove server...")

    server_cmd = [self.jove_server_path, 'server', '-v', '--port=%d' % self.jove_server_port]
    server_cmd += self.extra_server_args

    if self.unattended:
      self.serv_process = subprocess.Popen(server_cmd, stdin=subprocess.DEVNULL)
    else:
      self.serv_process = None

      p = self.pane("server")
      p.send_keys(" ".join(server_cmd)) # this is unreliable!!!

  def is_vm_ready(self):
    return any("login:" in row for row in self.pane("qemu").capture_pane())

  def wait_for_vm_ready(self, t=1.5):
    while not self.is_vm_ready():
      self.start_vm() # just in case

      print("waiting for VM...")
      time.sleep(t)
      self.pane("qemu").send_keys('')
      time.sleep(t)
      self.pane("qemu").send_keys('')
      time.sleep(t)

    print("VM ready.")

  def set_up_command_for_user(self, command):
    p = self.pane("ssh")
    p.send_keys("C-c", literal=False, enter=False)
    p.send_keys(" ".join(command), enter=False)

    self.sess.select_window("ssh")

  def fake_run_command_for_user(self, command):
    p = self.pane("ssh")
    p.send_keys("true || " + " ".join(command), enter=True)

  def set_up_ssh_command_for_user(self, command):
    self.set_up_command_for_user(["ssh"] + self.ssh_common_args + ['-p', str(self.guest_ssh_port), 'root@localhost'] + command)

  def fake_run_ssh_command_for_user(self, command):
    self.fake_run_command_for_user(["ssh", '-p', str(self.guest_ssh_port), 'root@localhost'] + command)

  def ssh_command(self, command, text=True):
    return subprocess.run(['ssh'] + self.ssh_common_args + ['-p', str(self.guest_ssh_port), 'root@localhost'] + command, capture_output=True, text=text)

  def ssh(self, command):
    return subprocess.run(['ssh'] + self.ssh_common_args + ['-p', str(self.guest_ssh_port), 'root@localhost'] + command)

  def scp(self, src, dst):
    return subprocess.run(['scp'] + self.ssh_common_args + ['-P', str(self.guest_ssh_port), src, 'root@localhost:' + dst])

  def update_jove(self):
    self.scp(self.jove_client_path, '/usr/local/bin/jove')

  def update_libjove_rt(self, multi_threaded):
    rtpath = self.jove_rt_mt_path if multi_threaded else self.jove_rt_st_path
    dstdir = "/tmp" if self.platform == "win" else "/lib"
    self.scp(rtpath, f'{dstdir}/libjove_rt.{self.dsoext}')

  def inputs_for_test(self, test, platform):
    inputs_path = f"{self.tests_dir}/{platform}/inputs/{test}.inputs"

    assert os.path.exists(inputs_path), "no input for %s" % test

    return eval(open(inputs_path, 'r').read())

  def is_stderr_connection_closed_by_remote_host(self, s):
    return "Connection to localhost closed by remote host.\n" == s

  def run_tests(self, tests, multi_threaded=True):
    assert self.is_ready()
    self.update_libjove_rt(multi_threaded=multi_threaded)

    print("running %d tests..." % len(tests))

    for test in tests:
      inputs = self.inputs_for_test(test, self.platform)

      for variant in self.variants:
        testbin_path = Path(self.tests_dir) / self.platform / "bin" / self.arch / f"{test}.{variant}"

        assert(testbin_path.is_file())

        self.scp(testbin_path, '/tmp/')
        testbin = f"/tmp/{testbin_path.name}"

        # establish clean slate
        self.ssh(["rm", "-rf", "/root/.jv", "/root/.jove"])

        # initialize jv
        self.ssh(["jove", "init", testbin])

        if self.platform != "win":
          # run inputs through prog, recovering code
          for input_args in inputs:
            self.ssh(["jove", "bootstrap", testbin] + input_args)

        # run inputs through recompiled binary
        jove_loop_args = ["jove", "loop", \
          f"--mt={int(multi_threaded)}", \
          "--connect", f"{self.iphost}:{str(self.jove_server_port)}"]
        if self.platform == "win":
          jove_loop_args += ["--lay-out-sections"]
        jove_loop_args += [testbin]

        # show user what we're doing
        if not self.unattended:
          self.fake_run_ssh_command_for_user(jove_loop_args + input_args)

        # for good measure, in case there is new code we run into
        for i in range(0, 2):
          for input_args in inputs:
            self.ssh(jove_loop_args + input_args)

        # compare result of executing testbin and recompiled testbin
        for input_args in inputs:
          count = 0
          while count < 20:
            p1 = self.ssh_command(self.run + [testbin] + input_args, text=True)
            p2 = self.ssh_command(jove_loop_args + input_args, text=True)

            if self.is_stderr_connection_closed_by_remote_host(p1.stderr) or \
               self.is_stderr_connection_closed_by_remote_host(p2.stderr):
              print('failed to ssh, wtf? trying again (%d)...' % count)
              time.sleep(1.25)
              count += 1
              continue

            return_neq = p1.returncode != p2.returncode
            stdout_neq = p1.stdout != p2.stdout
            stderr_neq = p1.stderr != p2.stderr

            failed = return_neq or stdout_neq
            if self.platform != "win": # wine prints a bunch of shit to stderr
              failed = failed or stderr_neq

            if failed:
              print("/////////\n///////// %s TEST FAILURE %s <%s>\n/////////" % \
                ("MULTI-THREADED" if multi_threaded else "SINGLE-THREADED", \
                 testbin, self.arch))

              if return_neq:
                print('%d != %d' % (p1.returncode, p2.returncode))
              if stdout_neq:
                print('<STDOUT>\n"%s"\n\n!=\n\n"%s"\n' % (p1.stdout, p2.stdout))
              if stderr_neq:
                print('<STDERR>\n"%s"\n\n!=\n\n"%s"\n' % (p1.stderr, p2.stderr))

              # make it easy for user to rerun failing test
              if not self.unattended:
                self.set_up_ssh_command_for_user(jove_loop_args + input_args)

              return 1
            break
          if count >= 20:
            print("SSH FAILURE!!!")
            return 1

    return 0

  def is_ready(self):
    return not (self.iphost is None)

  def get_ready(self, update_jove=True):
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
    self.iphost = self.ssh_command(['ip', 'route', 'show']).stdout.strip().split()[2]
    print("iphost: %s" % self.iphost)

    if update_jove:
      self.update_jove()

    #
    # start jove server
    #
    if self.unattended or self.create_serv:
      self.start_server()

  def __del__(self):
    if self.unattended:
      self.ssh(['systemctl', 'poweroff'])
      time.sleep(3)

      assert self.serv_process is not None
      try:
        self.serv_process.terminate()  # Gracefully terminate
        self.serv_process.wait(timeout=5)  # Wait for the process to exit
      except Exception as e:
        self.serv_process.kill()  # Forcefully kill if it doesn't exit
        print(f"Forced server subprocess termination: {e}")

      self.sess.kill_session()
