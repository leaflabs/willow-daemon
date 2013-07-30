#!/usr/bin/env python2

# Master test running script.
#
# This is a hack, but it works.
#
# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
#
#     YOU CAN'T RUN THIS SCRIPT AS-IS. YOU MUST RUN IT FROM THE BUILD
#     DIRECTORY AFTER RUNNING SCONS.
#
#     Like this:
#
#     $ scons
#     $ ./build/run-tests.py
#
# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

from __future__ import print_function

from glob import glob
import os
import os.path
import subprocess
import sys

# Make sure we're not being called from test/
if 'build' not in os.path.abspath(__file__):
    print('NOPE. First run scons, then run this script as installed in '
          'the build directory.',
          file=sys.stderr)
    sys.exit(1)

# Find out the build directory and hard-code some other paths we need.
build_dir = os.path.abspath(os.path.dirname(__file__))
build_libsng_dir = os.path.join(build_dir, 'libsng')
util_dir = os.path.abspath(os.path.join(build_dir, '..', 'util'))

# Path-related environment variables
os_path = os.environ['PATH'].split(os.pathsep)
test_path = os.pathsep.join([build_dir, util_dir] + os_path)
test_py_path = os.pathsep.join([build_dir, util_dir])

# Find the daemon and the dummy datanode
daemon_bin = os.path.join(build_dir, 'leafysd')
if not os.path.isfile(daemon_bin):
    print("Can't find daemon; expected it at %s" % daemon_bin,
          file=sys.stderr)
    sys.exit(1)
dummy_dnode_bin = os.path.join(build_dir, 'dummy-datanode')
if not os.path.isfile(dummy_dnode_bin):
    print("Can't find dummy data node, expected it at %s" % dummy_dnode_bin,
          file=sys.stderr)
    sys.exit(1)

# Grab all the test executables.
ctests = glob(os.path.join(build_dir, 'test-*'))
pytests = glob(os.path.join(build_dir, 'test_*.py'))

# Run the tests.
#
# Ideally, we'd use a single test case output format for both C and
# Python tests. While check (the C test framework) has supported
# subunit output for a while, the Ubuntu package for it disables this
# support, at least as of 0.9.8-1.1ubuntu1.
#
# As a workaround, we partition the C and Python tests, use check's
# normal output for C, and use unittest's output for Python.
def fresh_test_env():
    return { 'PATH': test_path,
             'PYTHONPATH': test_py_path,
             'TEST_DAEMON_PATH': daemon_bin,
             'TEST_DUMMY_DNODE_PATH': dummy_dnode_bin,
             'LD_LIBRARY_PATH': build_libsng_dir }

print('=' * 70)
print('Running C tests')
for t in sorted(ctests):
    subprocess.call([t], env=fresh_test_env())

print('=' * 70)
print('Running Python tests')
subprocess.call(['python', '-m', 'unittest', 'discover', '-s', build_dir],
                env=fresh_test_env())
