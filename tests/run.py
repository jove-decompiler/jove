#!/usr/bin/python3

import tempfile
import subprocess
import sys
import pathlib
import argparse

parser = argparse.ArgumentParser(description='Run tests.')
parser.add_argument('tests', metavar='T', type=str, nargs='+', help='tests to execute')
parser.add_argument('-a', dest='arch', type=str, required=True, help='specify architecture')

args = parser.parse_args()
print(args)

tests_dir = pathlib.Path(__file__).parent.resolve()

d = tempfile.TemporaryDirectory()
print(d.name)

bringup_path = str(tests_dir) + "/../mk-deb-vm/bringup.sh"
print(bringup_path)

subprocess.run(["sudo", bringup_path, "-a", args.arch, "-o", d.name], check=True)

#sshpass -p root ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o LogLevel=quiet -p 10022 root@localhost 'false'
