#!/usr/bin/env python

from __future__ import print_function
import os.path
import sys
from time import time

from daemon_control import *

def usage(exit=True):
    print("usage: acquire.py <start|stop|save_stream file nsamples>",
          file=sys.stderr)
    if exit:
        sys.exit(1)

if len(sys.argv) < 2:
    usage()

# Parse arguments.
arg = sys.argv[1]
if arg == 'start' or arg == 'stop':
    if len(sys.argv) != 2:
        print("'%s' doesn't take arguments" % arg, file=sys.stderr)
        usage()
    enable = True if arg == 'start' else False
elif arg == 'save_stream':
    if len(sys.argv) != 4:
        print('Wrong arguments to save_stream, expected: file nsamples',
              file=sys.stderr)
        usage()
    try:
        fpath = os.path.abspath(sys.argv[2])
        nsamples = int(sys.argv[3])
    except:
        print('Invalid arguments to save_stream, expected: file nsamples',
              file=sys.stderr)
        usage()
else:
    usage()

# Build the command.
if arg == 'start' or arg == 'stop':
    cmd = ControlCommand(type=ControlCommand.ACQUIRE)
    cmd.acquire.exp_cookie = long(time())
    cmd.acquire.enable = enable
else:
    cmd = ControlCommand(type=ControlCommand.STORE)
    cmd.store.path = fpath
    cmd.store.nsamples = nsamples

# Run command; print the result.
resps = do_control_cmds([cmd])
if resps is None:
    print("Didn't get a response", file=sys.stderr)
    sys.exit(1)
print(resps[0])
