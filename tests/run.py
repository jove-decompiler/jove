#!/usr/bin/python3

import tempfile
import subprocess
import sys
import argparse
import os
import time
import re
import atexit
from pathlib import Path

parser = argparse.ArgumentParser(description='Run tests.')
parser.add_argument('tests', metavar='T', type=str, nargs='+', help='tests to execute')
parser.add_argument('-a', dest='arch', type=str, required=True, help='specify architecture')
parser.add_argument('--preexisting', dest='preexisting', type=str, help='specify preexisting directory')

args = parser.parse_args()

tests_dir = Path(__file__).parent.resolve()

jove_server_path = '%s/../llvm-project/build/bin/jove-%s' % (tests_dir, args.arch)
assert(Path(jove_server_path).is_file())

jove_client_path = '%s/../llvm-project/%s_build/bin/jove-%s' % (tests_dir, args.arch, args.arch)
assert(Path(jove_client_path).is_file())

jove_rt_path = '%s/../bin/%s/libjove_rt.so' % (tests_dir, args.arch)
assert(Path(jove_rt_path).is_file())

#td_path = "/root/deb-vm-" + args.arch
#os.mkdir(td_path)
#d = td_path

td = tempfile.TemporaryDirectory()
d = td.name

arch2ports = dict()
arch2ports["i386"]     = 10023
arch2ports["x86_64"]   = 10024
arch2ports["aarch64"]  = 10025
arch2ports["mipsel"]   = 10026
arch2ports["mips"]     = 10027
arch2ports["mips64el"] = 10028

guest_ssh_port = arch2ports[args.arch]
jove_server_port = guest_ssh_port - 5000

if args.preexisting is None:
  bringup_path = '%s/../mk-deb-vm/bringup.sh' % str(tests_dir)

  subprocess.run(['sudo', bringup_path, '-a', args.arch, '-s', 'bookworm', '-o', d, '-p', str(guest_ssh_port), '-f'], check=True)
else:
  d = args.preexisting

os.mkfifo('%s/x.in' % d)
os.mkfifo('%s/x.out' % d)

cp = subprocess.Popen(['cat', '%s/x.out' % d], stdout=open('%s/stdout.txt' % d, 'wb', buffering=0), stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

os.chdir(d)
qp = subprocess.Popen(['%s/run.sh' % d], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

def cleanup():
  cp.kill()
  qp.kill()

atexit.register(cleanup)

def serial_write(s, t=0.5):
  if qp.poll() != None or cp.poll() != None:
    return False

  inf = open('%s/x.in' % d, 'wb', buffering=0)
  inf.write(s.encode())
  inf.close()

  time.sleep(t)

  return True

ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
def strip_ansi_escape_sequences(s):
  return ansi_escape.sub('', s)

def serial_tail(n=1):
  completed_process = subprocess.run(['tail', '-n', str(n), '%s/stdout.txt' % d], capture_output=True, text=True)
  return strip_ansi_escape_sequences(completed_process.stdout)

def ssh_command(command, text=True):
  return subprocess.run(['ssh', '-o', 'UserKnownHostsFile=/dev/null', '-o', 'StrictHostKeyChecking=no', '-o', 'LogLevel=quiet', '-p', str(guest_ssh_port), 'root@localhost'] + command, capture_output=True, text=text)

def ssh(command):
  return subprocess.run(['ssh', '-o', 'UserKnownHostsFile=/dev/null', '-o', 'StrictHostKeyChecking=no', '-o', 'LogLevel=quiet', '-p', str(guest_ssh_port), 'root@localhost'] + command)

def scp(src, dst):
  return subprocess.run(['scp', '-o', 'UserKnownHostsFile=/dev/null', '-o', 'StrictHostKeyChecking=no', '-o', 'LogLevel=quiet', '-P', str(guest_ssh_port), src, 'root@localhost:' + dst])

def inputs_for_test(test):
  inputs_path = '%s/inputs/%s.inputs' % (tests_dir, test)
  assert(Path(inputs_path).is_file())

  return eval(open(inputs_path, 'r').read())

#
# wait for system to boot up
#
print("waiting for system to boot...")

time.sleep(0.5)

while not serial_tail().strip().endswith("login:"):
  assert(serial_write("\n"))

print("system booted.")

#
# get IP of host seen by guest
#
iphost = ssh_command(['ip', 'route', 'show']).stdout.strip().split()[2]
print("iphost: %s" % iphost)

#
# start jove server
#
jp = subprocess.Popen([jove_server_path, 'server', '-v', '--port=%d' % jove_server_port], stdin=subprocess.DEVNULL)

#
# prepare to run jove under emulation
#
scp(jove_client_path, '/usr/local/bin/jove')
scp(jove_rt_path, '/lib/')

def run_tests():
  for test in args.tests:
    test_inputs = inputs_for_test(test)
    test_bin = '%s/bin/%s/%s' % (tests_dir, args.arch, test)

    for variant in ["exe", "pic"]:
      test_bin_path = '%s.%s' % (test_bin, variant);
      test_bin_name = Path(test_bin_path).name

      print("test %s" % test_bin_path)

      assert(Path(test_bin_path).is_file())

      scp(test_bin_path, '/tmp/')

      test_guest_path = '/tmp/%s' % test_bin_name

      ssh(["rm", "-f", "/root/.jv"]) # FIXME

      ssh(["jove", "init", test_guest_path])
      for input_args in test_inputs:
        ssh(["jove", "bootstrap", test_guest_path] + input_args)

      for i in range(0, 2):
        for input_args in test_inputs:
          ssh(["jove", "loop", "-x", "--connect", "%s:%d" % (iphost, jove_server_port), test_guest_path] + input_args)

      for input_args in test_inputs:
        p1 = ssh_command([test_guest_path] + input_args, text=True)
        p2 = ssh_command(["jove", "loop", "-x", "--connect", "%s:%d" % (iphost, jove_server_port), test_guest_path] + input_args, text=True)

        if p2.returncode != 0 and p1.returncode == 0:
          print("TESTS FAILURE_1 %s [%s]" % (test_bin_path, args.arch))
          return 1

        stdout_neq = p1.stdout != p2.stdout
        stderr_neq = p1.stderr != p2.stderr
        if stdout_neq or stderr_neq:
          if stdout_neq:
            print("TESTS FAILURE_2 [%s] %s\n\n\"%s\"\n\n!=\n\n\"%s\"\n\n" % (args.arch, test_bin_path, p1.stdout, p2.stdout))
          if stderr_neq:
            print("TESTS FAILURE_2 [%s] %s\n\n\"%s\"\n\n!=\n\n\"%s\"\n\n" % (args.arch, test_bin_path, p1.stderr, p2.stderr))
          return 1

  return 0

exit_code = run_tests()

#
# power off system
#
print("powering off system...")

ssh(['systemctl', 'poweroff'])

qp.communicate()
cp.communicate()
jp.kill()

sys.exit(exit_code)
