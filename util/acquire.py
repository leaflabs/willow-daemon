#!/usr/bin/env python

from __future__ import print_function
import argparse
import os.path
import sys
from time import time

from daemon_control import *

##
## Command handling
##

def acquire(enable):
    cmd = ControlCommand(type=ControlCommand.ACQUIRE)
    if enable:
        cmd.acquire.exp_cookie = long(time())
    cmd.acquire.enable = enable
    return [cmd]

def start(args):
    return acquire(True)

def stop(args):
    return acquire(False)

def save_stream(args):
    fpath = os.path.abspath(args.file)
    nsamples = args.nsamples
    cmd = ControlCommand(type=ControlCommand.STORE)
    cmd.store.path = os.path.abspath(fpath)
    cmd.store.nsamples = nsamples
    return [cmd]

##
## Argument parsing
##

def no_arg_parser(cmd, description):
    return argparse.ArgumentParser(prog=cmd, description=description)

save_stream_parser = argparse.ArgumentParser(
    prog='save_stream',
    description='Save live streaming data to disk')
save_stream_parser.add_argument('file',
                                help='File to store samples in')
save_stream_parser.add_argument('nsamples', type=int,
                                help='Number of samples to try storing')

COMMAND_HANDLING = {
    'start': (start, no_arg_parser('start', 'Start acquiring to disk')),
    'stop': (stop, no_arg_parser('stop', 'Stop acquiring to disk')),
    'save_stream': (save_stream, save_stream_parser)
}

##
## main()
##

def usage():
    print('usage: acquire.py command [[-h] command_args ...]\n'
          'Commands:\n'
          '%s' % ''.join(['\t%s: %s\n' % (s, h_p[1].description)
                          for s, h_p in COMMAND_HANDLING.iteritems()]),
          end='', file=sys.stderr)
    sys.exit(1)

def main():
    if len(sys.argv) < 2:
        usage()
    cmd, cmd_args = sys.argv[1], sys.argv[2:]
    if cmd not in COMMAND_HANDLING:
        usage()
    handler, parser = COMMAND_HANDLING[cmd]
    cmds = handler(parser.parse_args(cmd_args))
    resps = do_control_cmds(cmds)
    if resps is None:
        print("Didn't get a response", file=sys.stderr)
        sys.exit(1)
    for resp in resps:
        print(resp, end='')

if __name__ == '__main__':
    main()
