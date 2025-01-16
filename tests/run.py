#!/usr/bin/python3

import os
import argparse
import sys
from pathlib import Path
from tester import JoveTester

def parse_arguments():
  parser = argparse.ArgumentParser(description='Run tests.')
  parser.add_argument('-a', dest='arch', type=str, required=True, help='specify architecture')
  parser.add_argument('-p', dest='platform', type=str, required=True, help='specify platform (linux, win)')
  parser.add_argument('-u', '--unattended', action='store_true', help='Run in unattended mode')
  parser.add_argument('--just-update-jove', action='store_true', help='Update /usr/local/bin/jove and exit')
  parser.add_argument('--single-threaded', nargs='+', help='Single-threaded tests')
  parser.add_argument('--multi-threaded', nargs='+', help='Multi-threaded tests')

  return parser.parse_args()

def main():
  args = parse_arguments()

  tests_dir = str(Path(__file__).parent.resolve())

  unattended = args.unattended

  unattended_env = os.getenv("JOVE_TEST_UNATTENDED")
  if not (unattended_env is None) and unattended_env == "1":
    unattended = True

  extra_server_args = []
  extra_bringup_args = []

  extra_server_args_env = os.getenv("JOVE_TEST_SERVER_ARGS")
  extra_bringup_args_env = os.getenv("JOVE_TEST_BRINGUP_ARGS")

  if not (extra_server_args_env is None):
    extra_server_args = extra_server_args_env.split(',')

  if not (extra_bringup_args_env is None):
    extra_bringup_args = extra_bringup_args_env.split(',')

  tester = JoveTester(tests_dir, arch=args.arch, platform=args.platform, \
                      extra_server_args=extra_server_args, \
                      extra_bringup_args=extra_bringup_args, \
                      unattended=unattended)

  if args.just_update_jove:
    tester.update_jove()
    return 0

  tester.get_ready()

  if args.single_threaded:
      print(f"running single-threaded tests ({args.single_threaded})")

  if args.single_threaded:
    ret = tester.run_tests(args.single_threaded, multi_threaded=False)
    if ret != 0:
      return ret

  if args.multi_threaded:
      print(f"running multi-threaded tests: ({args.multi_threaded})")

  if args.multi_threaded:
    ret = tester.run_tests(args.multi_threaded, multi_threaded=True)
    if ret != 0:
      return ret

  return 0

if __name__ == "__main__":
  rc = main()
