#!/usr/bin/env python2.7

# Master test running script.
#
# This is a hack, but it works.
#
# This expects a WiredLeaf board listening at DEFAULT_LIVE_DNODE_ADDR,
# port 1369. To run tests against dummy-datanode, set DO_IT_LIVE=0 in
# the environment. Note that some tests only run against the
# dummy-datanode.
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

from fnmatch import fnmatch
import os
import os.path
import subprocess
import sys

DEFAULT_LIVE_DNODE_ADDR = '192.168.1.2'

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

# Tests the user wants
tests_to_run = sys.argv[1:]

# Does the user want us to use the dummy datanode?
if 'DO_IT_LIVE' in os.environ:
    do_it_live = bool(int(os.environ['DO_IT_LIVE']))
else:
    do_it_live = True
dnode_ip = DEFAULT_LIVE_DNODE_ADDR if do_it_live else 'localhost'

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
ctests_all = [t for t in os.listdir(build_dir) if fnmatch(t, 'test-*')]
pytests_all = [t for t in os.listdir(build_dir)
               if fnmatch(t, 'test_*.py') and t != 'test_helpers.py']
if tests_to_run:
    ctests = []
    pytests = []
    for ttr in tests_to_run:
        if 'test-' + ttr in ctests_all:
            ctests.append('test-' + ttr)
        elif 'test_' + ttr + '.py' in pytests_all:
            pytests.append('test_' + ttr + '.py')
        else:
            print(('No such test as "%s"; ' % ttr) +
                  'be sure to omit the test-/test_/.py parts',
                  file=sys.stderr)
            sys.exit(1)
else:
    ctests = ctests_all
    pytests = pytests_all

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
             'TEST_DO_IT_LIVE': str(int(do_it_live)),
             'TEST_DNODE_IP': dnode_ip,
             'LD_LIBRARY_PATH': build_libsng_dir }

def kill_stray(proc):
    if subprocess.call(['killall', proc],
                       stderr=subprocess.STDOUT,
                       stdout=subprocess.PIPE) == 0:
        print('Oops: killed a stray %s' % proc)

oldcwd = os.getcwd()
os.chdir(build_dir)
try:
    print('=' * 70)
    if do_it_live:
        print('Using WiredLeaf board at IP address %s' %
              DEFAULT_LIVE_DNODE_ADDR)
    else:
        print('Using the dummy datanode')

    if ctests:
        print('=' * 70)
        print('Running C tests:')
        for t in sorted(ctests):
            subprocess.call([t], env=fresh_test_env())
        if pytests:
            print()

    if pytests:
        print('=' * 70)
        print('Running Python tests:')
        for t in sorted(pytests):
            print(t[len('test_'):-len('.py')])
            tmod = t[:-len('.py')]
            subprocess.call(['python', '-m', 'unittest', '-q', tmod],
                            env=fresh_test_env())
            print()
finally:
    os.chdir(oldcwd)
    kill_stray('leafysd')
    kill_stray('dummy-datanode')
