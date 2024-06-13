from pathlib import Path
import subprocess
import tempfile
import libtmux
import time
import os

class JoveTester:
  ARCH2PORT = {
    'i386'    : 10023,
    'x86_64'  : 10024,
    'aarch64' : 10025,
    'mipsel'  : 10026,
    'mips'    : 10027,
    'mips64el': 10028
  }

  WINDOWS = [
    'qemu',
    'server',
    'ssh'
  ]

  def __init__(self, tests_dir, tests, arch, unattended=False):
    self.tests_dir = tests_dir
    self.tests = tests
    self.arch = arch
    self.unattended = unattended

    assert arch in JoveTester.ARCH2PORT, "invalid arch"

    self.guest_ssh_port = JoveTester.ARCH2PORT[self.arch]
    self.jove_server_port = self.guest_ssh_port - 5000

    self.find_things()

    self.vm_dir = os.getenv("JOVE_VM_" + arch.upper())
    if self.vm_dir is None:
      self.td = tempfile.TemporaryDirectory()
      self.vm_dir = self.td.name
    else:
      assert os.path.isdir(self.vm_dir), "VM path not directory"

    self.wins = [None for _ in JoveTester.WINDOWS]

  def find_things(self):
    self.jove_server_path = '%s/../llvm-project/build/bin/jove-%s' % (self.tests_dir, self.arch)
    assert Path(self.jove_server_path).is_file(), "missing host jove binary"

    self.jove_client_path = '%s/../llvm-project/%s_build/bin/jove-%s' % (self.tests_dir, self.arch, self.arch)
    assert Path(self.jove_client_path).is_file(), "missing guest jove binary"

    self.jove_rt_path = '%s/../bin/%s/libjove_rt.st.so' % (self.tests_dir, self.arch)
    assert Path(self.jove_rt_path).is_file(), "missing jove runtime"

    self.bringup_path = '%s/../mk-deb-vm/bringup.sh' % self.tests_dir
    assert Path(self.bringup_path).is_file(), "missing mk-deb-vm/bringup.sh"

  def session_name(self):
    return "jove_" + self.arch

  def find_windows(self):
    self.sess = None
    self.wins = [None for _ in JoveTester.WINDOWS]
    tmux = libtmux.Server()

    for sess in tmux.sessions:
      if sess.name == self.session_name():
        self.sess = sess
        break

    assert not (self.sess is None)

    for win in self.sess.windows:
      try:
        self.wins[JoveTester.WINDOWS.index(win.name)] = win
      except ValueError:
        continue

  def find_or_create_tmux_session(self):
    self.sess = None
    res = [False for _ in JoveTester.WINDOWS]
    tmux = libtmux.Server()

    for sess in tmux.sessions:
      if sess.name == self.session_name():
        self.sess = sess
        break

    if self.sess is None:
      print('creating tmux session "%s"' % self.session_name())

      self.sess = tmux.new_session(session_name=self.session_name(), window_name=JoveTester.WINDOWS[0])

      assert self.sess.windows[0].name == JoveTester.WINDOWS[0]

      self.wins[0] = self.sess.windows[0]
      res[0] = True
    else:
      self.find_windows()

    for idx in range(0, len(self.wins)):
      if self.wins[idx] is None:
        res[idx] = True
        self.wins[idx] = self.sess.new_window(window_name=JoveTester.WINDOWS[idx])

    return res

  def vm_run_path(self):
    return self.vm_dir + "/run.sh"

  def exists_vm(self):
    run_path = self.vm_run_path()
    return os.path.exists(run_path) and Path(run_path).is_file()

  def create_vm(self):
    print("creating VM...")

    subprocess.run(['sudo', self.bringup_path, '-a', self.arch, '-s', 'bookworm', '-o', self.vm_dir, '-p', str(self.guest_ssh_port)], check=True)

  def qemu_pane(self):
    self.find_windows()
    return self.wins[0].attached_pane

  def server_pane(self):
    self.find_windows()
    return self.wins[1].attached_pane

  def ssh_pane(self):
    self.find_windows()
    return self.wins[2].attached_pane

  def start_vm(self):
    print("starting VM...")

    qp = self.qemu_pane()

    qp.send_keys('clear')
    qp.send_keys('cd "%s"' % self.vm_dir)
    qp.send_keys('./run.sh')

  def start_server(self):
    print("starting jove server...")

    command = [self.jove_server_path, 'server', '-v', '--port=%d' % self.jove_server_port]

    pane = self.server_pane()
    pane.send_keys(" ".join(command))

  def is_vm_ready(self):
    qp = self.qemu_pane()

    return any("login:" in row for row in qp.capture_pane())

  def wait_for_vm_ready(self, t=1.5):
    qp = self.qemu_pane()

    while not self.is_vm_ready():
      print("waiting for VM...")

      time.sleep(t)
      qp.send_keys('')

    print("VM ready.")

  def set_up_command_for_user(self, command):
    self.sess.select_window("ssh")

    pane = self.ssh_pane()
    pane.send_keys("C-c", literal=False, enter=False)
    pane.send_keys(" ".join(command), enter=False)

  def fake_run_command_for_user(self, command):
    pane = self.ssh_pane()
    pane.send_keys("true || " + " ".join(command), enter=True)

  def set_up_ssh_command_for_user(self, command):
    self.set_up_command_for_user(["ssh", '-p', str(self.guest_ssh_port), 'root@localhost'] + command)

  def fake_run_ssh_command_for_user(self, command):
    self.fake_run_command_for_user(["ssh", '-p', str(self.guest_ssh_port), 'root@localhost'] + command)

  def ssh_command(self, command, text=True):
    return subprocess.run(['ssh', '-o', 'UserKnownHostsFile=/dev/null', '-o', 'StrictHostKeyChecking=no', '-o', 'LogLevel=quiet', '-p', str(self.guest_ssh_port), 'root@localhost'] + command, capture_output=True, text=text)

  def ssh(self, command):
    return subprocess.run(['ssh', '-o', 'UserKnownHostsFile=/dev/null', '-o', 'StrictHostKeyChecking=no', '-o', 'LogLevel=quiet', '-p', str(self.guest_ssh_port), 'root@localhost'] + command)

  def scp(self, src, dst):
    return subprocess.run(['scp', '-o', 'UserKnownHostsFile=/dev/null', '-o', 'StrictHostKeyChecking=no', '-o', 'LogLevel=quiet', '-P', str(self.guest_ssh_port), src, 'root@localhost:' + dst])

  def prepare_run_tests(self):
    print("preparing to run tests...")

    self.scp(self.jove_client_path, '/usr/local/bin/jove')
    self.scp(self.jove_rt_path, '/lib/libjove_rt.so')

  def inputs_for_test(self, test):
    inputs_path = '%s/inputs/%s.inputs' % (self.tests_dir, test)

    assert os.path.exists(inputs_path), "no input for %s" % test

    return eval(open(inputs_path, 'r').read())

  def run_tests(self):
    print("running %d tests..." % len(self.tests))

    for test in self.tests:
      test_inputs = self.inputs_for_test(test)
      test_bin = '%s/bin/%s/%s' % (self.tests_dir, self.arch, test)

      for variant in ["exe", "pic"]:
        test_bin_path = '%s.%s' % (test_bin, variant);
        test_bin_name = Path(test_bin_path).name

        print("test %s" % test_bin_path)

        assert(Path(test_bin_path).is_file())

        self.scp(test_bin_path, '/tmp/')

        test_guest_path = '/tmp/%s' % test_bin_name

        self.ssh(["rm", "-rf", "/root/.jv", "/root/.jove"]) # FIXME

        self.ssh(["jove", "init", test_guest_path])
        for input_args in test_inputs:
          self.ssh(["jove", "bootstrap", test_guest_path] + input_args)

        jove_loop_args = ["jove", "loop", "--mt=0", "--optimize", "--connect", "%s:%d" % (self.iphost, self.jove_server_port), test_guest_path]

        if not self.unattended:
          self.fake_run_ssh_command_for_user(jove_loop_args + input_args)

        for i in range(0, 2):
          for input_args in test_inputs:
            self.ssh(jove_loop_args + input_args)

        for input_args in test_inputs:
          p1 = self.ssh_command([test_guest_path] + input_args, text=True)
          p2 = self.ssh_command(jove_loop_args + input_args, text=True)

          return_neq = p1.returncode != p2.returncode
          stdout_neq = p1.stdout != p2.stdout
          stderr_neq = p1.stderr != p2.stderr

          failed = return_neq or stdout_neq or stderr_neq
          if failed:
            print("/////////\n///////// TEST FAILURE %s <%s>\n/////////" % (test_bin_path, self.arch))
            if return_neq:
              print('%d != %d' % (p1.returncode, p2.returncode))
            if stdout_neq:
              print('<STDOUT>\n"%s"\n\n!=\n\n"%s"\n' % (p1.stdout, p2.stdout))
            if stderr_neq:
              print('<STDERR>\n"%s"\n\n!=\n\n"%s"\n' % (p1.stderr, p2.stderr))

            if not self.unattended:
              self.set_up_ssh_command_for_user(jove_loop_args)

            return 1

    return 0

  def run(self):
    create_list = self.find_or_create_tmux_session()
    create_qemu, create_serv, create_ssh = tuple(create_list)

    if create_qemu:
      if not self.exists_vm():
        self.create_vm()
      self.start_vm()

    if not self.is_vm_ready():
      self.wait_for_vm_ready()

    #
    # get IP of host seen by guest
    #
    self.iphost = self.ssh_command(['ip', 'route', 'show']).stdout.strip().split()[2]
    print("iphost: %s" % self.iphost)

    #
    # start jove server
    #
    if create_serv:
      self.start_server()

    self.prepare_run_tests()

    #
    # run tests
    #
    rc = self.run_tests()

    if self.unattended:
      if create_qemu:
        self.ssh(['systemctl', 'poweroff'])
      if create_serv:
        self.server_pane().send_keys("C-c", literal=False, enter=False)

      self.find_windows()
      for i in range(0, len(create_list)):
        if create_list[i]:
          self.sess.kill_window(JoveTester.WINDOWS[i])

    return rc
