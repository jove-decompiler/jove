#!/usr/bin/python3

import tempfile
import subprocess
import sys
import pathlib
import argparse
import os
import time

parser = argparse.ArgumentParser(description='Run tests.')
parser.add_argument('tests', metavar='T', type=str, nargs='+', help='tests to execute')
parser.add_argument('-a', dest='arch', type=str, required=True, help='specify architecture')

args = parser.parse_args()
print(args)

tests_dir = pathlib.Path(__file__).parent.resolve()

d = tempfile.TemporaryDirectory()
print(d.name)

bringup_path = '%s/../mk-deb-vm/bringup.sh' % str(tests_dir)
print(bringup_path)

subprocess.run(['sudo', bringup_path, '-a', args.arch, '-o', d.name, '-f'], check=True)

os.mkfifo('%s/x.in' % d.name)
os.mkfifo('%s/x.out' % d.name)

cp = subprocess.Popen(['cat', '%s/x.out' % d.name], stdout=open('%s/stdout.txt' % d.name, 'wb', buffering=0), stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

os.chdir(d.name)
qp = subprocess.Popen(['%s/run.sh' % d.name], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def serial_write(s):
  if qp.poll() != None:
    return False

  inf = open('%s/x.in' % d.name, 'wb', buffering=0)
  inf.write(s.encode())
  inf.close()
  return True

while True:
  assert(serial_write("\n"))
  time.sleep(1)
  tp = subprocess.run(['tail', '-n', '1', '%s/stdout.txt' % d.name], capture_output=True, text=True)
  if tp.stdout.strip().endswith("login:"):
    print("found login:")
    break

while True:
  if serial_write("root\n"):
    time.sleep(1)
  else:
    break

  if serial_write("root\n"):
    time.sleep(3)
  else:
    break

  if serial_write("systemctl poweroff\n"):
    time.sleep(10)
  else:
    break

qp.communicate()
cp.communicate()
