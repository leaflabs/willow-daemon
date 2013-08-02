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

if not (len(sys.argv) == 2 or len(sys.argv) == 4):
    usage()
elif sys.argv[1] == 'start':
    enable = True
elif sys.argv[1] == 'stop':
    enable = False
elif sys.argv[1] == 'save_stream':
    enable = None
    try:
        fpath = os.path.abspath(sys.argv[2])
        nsamples = int(sys.argv[3])
    except:
        usage(exit=False)
        raise

else:
    usage()

if enable is not None:
    cmd = ControlCommand(type=ControlCommand.ACQUIRE)
    cmd.acquire.exp_cookie = long(time())
    cmd.acquire.enable = enable
else:
    cmd = ControlCommand(type=ControlCommand.STORE)
    cmd.store.path = fpath
    cmd.store.nsamples = nsamples

resps = do_control_cmds([cmd])
if resps is None:
    print("Didn't get a response", file=sys.stderr)
    sys.exit(1)
print(resps[0])
