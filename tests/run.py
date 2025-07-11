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

  group = parser.add_mutually_exclusive_group(required=True)
  group.add_argument('--local', action='store_true',
                     help="Run tests locally")
  group.add_argument('--remote', action='store_true',
                     help="Run tests remotely")
  group.add_argument('--local-and-remote', action='store_true',
                     help="Run tests both locally and remotely")

  return parser.parse_args()

def main():
  args = parse_arguments()

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

  tester = JoveTester(arch=args.arch, platform=args.platform, \
                      extra_server_args=extra_server_args, \
                      extra_bringup_args=extra_bringup_args, \
                      unattended=unattended)

  if args.just_update_jove:
    tester.get_remote_ready()
    tester.update_jove()
    del tester
    return 0

  test_configs = []
  if args.single_threaded:
      test_configs.append((args.single_threaded, False))
  if args.multi_threaded:
      test_configs.append((args.multi_threaded, True))

  run_modes = []
  if args.local or args.local_and_remote:
      run_modes.append(False)  # Local
  if args.remote or args.local_and_remote:
      run_modes.append(True)   # Remote

  remoteReady = False

  # Run all combinations of test types and modes
  for tests, multi_flag in test_configs:
    label = 'multi-threaded' if multi_flag else 'single-threaded'
    for remote in run_modes:
      if remote and not remoteReady:
        tester.get_remote_ready()
        remoteReady = True
      mode = 'remote' if remote else 'local'
      print(f"Running {label} {mode} tests...")
      ret = tester.run_tests(
        tests,
        multi_threaded=multi_flag,
        remote=remote
      )
      if ret:
        del tester
        return ret

  del tester
  return 0

if __name__ == "__main__":
  sys.exit(main())
