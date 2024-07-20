#!/usr/bin/python3

import os
import argparse
import sys
from pathlib import Path
from tester import JoveTester

def parse_arguments():
  parser = argparse.ArgumentParser(description='Run tests.')
  parser.add_argument('tests', metavar='T', type=str, nargs='+', help='tests to execute')
  parser.add_argument('-a', dest='arch', type=str, required=True, help='specify architecture')
  parser.add_argument('-u', '--unattended', action='store_true', help='Run in unattended mode')

  return parser.parse_args()

def main():
  args = parse_arguments()

  tests_dir = str(Path(__file__).parent.resolve())

  unattended = args.unattended

  unattended_env = os.getenv("JOVE_RUN_TESTS_UNATTENDED")
  if not (unattended_env is None) and unattended_env == "1":
    unattended = True

  newroot_losetup = os.getenv("JOVE_CHROOT_LOSETUP")

  extra_server_args = []
  extra_bringup_args = []

  extra_server_args_env = os.getenv("JOVE_TEST_SERVER_ARGS")
  extra_bringup_args_env = os.getenv("JOVE_TEST_BRINGUP_ARGS")

  if not (extra_server_args_env is None):
    extra_server_args = extra_server_args_env.split(',')

  if not (extra_bringup_args_env is None):
    extra_bringup_args = extra_bringup_args_env.split(',')

  tester = JoveTester(tests_dir, args.tests, args.arch, \
                      extra_server_args=extra_server_args, \
                      extra_bringup_args=extra_bringup_args, \
                      newroot_losetup=newroot_losetup, \
                      unattended=unattended)
  return tester.run()

if __name__ == "__main__":
  rc = main()
  sys.exit(rc)
