#!/usr/bin/env python

from __future__ import print_function
from time import time
import sys

from daemon_control import *

def usage():
    print("usage: acquire.py <start|stop>", file=sys.stderr)
    sys.exit(1)

if len(sys.argv) != 2:
    usage()
elif sys.argv[1] == 'start':
    enable = True
elif sys.argv[1] == 'stop':
    enable = False
else:
    usage()

cmd = ControlCommand(type=ControlCommand.ACQUIRE)
cmd.acquire.exp_cookie = long(time())
cmd.acquire.enable = enable
resps = do_control_cmds([cmd])
if resps is None:
    print("Didn't get a response", file=sys.stderr)
    sys.exit(1)
print(resps[0])
