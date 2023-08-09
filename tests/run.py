#!/usr/bin/python3

import tempfile
import subprocess
import sys
import pathlib
import argparse
import os
import time
import re

parser = argparse.ArgumentParser(description='Run tests.')
parser.add_argument('tests', metavar='T', type=str, nargs='+', help='tests to execute')
parser.add_argument('-a', dest='arch', type=str, required=True, help='specify architecture')
parser.add_argument('--preexisting', dest='preexisting', type=str, help='specify preexisting directory')

args = parser.parse_args()

td = tempfile.TemporaryDirectory()
d = td.name

if args.preexisting is None:
  tests_dir = pathlib.Path(__file__).parent.resolve()
  bringup_path = '%s/../mk-deb-vm/bringup.sh' % str(tests_dir)

  subprocess.run(['sudo', bringup_path, '-a', args.arch, '-o', d, '-f'], check=True)
else:
  d = args.preexisting

os.mkfifo('%s/x.in' % d)
os.mkfifo('%s/x.out' % d)

cp = subprocess.Popen(['cat', '%s/x.out' % d], stdout=open('%s/stdout.txt' % d, 'wb', buffering=0), stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

os.chdir(d)
qp = subprocess.Popen(['%s/run.sh' % d], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

def serial_write(s, t=0.5):
  if qp.poll() != None or cp.poll() != None:
    return False

  inf = open('%s/x.in' % d, 'wb', buffering=0)
  inf.write(s.encode())
  inf.close()

  time.sleep(t)

  return True

def strip_ansi_escape_sequences(s):
  ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
  return ansi_escape.sub('', s)

def serial_tail(n=1):
  completed_process = subprocess.run(['tail', '-n', str(n), '%s/stdout.txt' % d], capture_output=True, text=True)
  return strip_ansi_escape_sequences(completed_process.stdout)

#
# wait for system to boot up
#
print("waiting for system to boot...")

time.sleep(0.5)

while not serial_tail().strip().endswith("login:"):
  assert(serial_write("\n"))

print("system booted.")

#
# log in to system
#
print("logging into system...")

assert(serial_write("root\n", 0.8) and serial_write("root\n"))

serial_write("ip route show\n")
print('\n\"%s\"\n' % serial_tail(5).strip())
print(serial_tail(5).strip().split()[2])

#
# power off system
#
print("powering off system...")

assert(serial_write("systemctl poweroff\n"))

qp.communicate()
cp.communicate()
