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

  tester = JoveTester(tests_dir, args.tests, args.arch, unattended)
  return tester.run()

if __name__ == "__main__":
  rc = main()
  sys.exit(rc)
