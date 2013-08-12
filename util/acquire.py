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

def err_regs(args):
    return read_err_regs()

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

def stream(args):
    cmd = ControlCommand(type=ControlCommand.STREAM)
    if args.type == 'sample':
        cmd.stream.sample_type = BOARD_SAMPLE
    else:
        cmd.stream.sample_type = BOARD_SUBSAMPLE
    if args.force_daq_reset:
        cmd.stream.force_daq_reset = True
    try:
        aton = socket.inet_aton(args.address)
    except socket.error:
        print('Invalid address', args.address, file=sys.stderr)
        sys.exit(1)
    cmd.stream.dest_udp_addr4 = struct.unpack('!l', aton)[0]
    if args.port <= 0 or args.port >= 0xFFFF:
        print('Invalid port', args.port, file=sys.stderr)
        sys.exit(1)
    cmd.stream.dest_udp_port = args.port
    cmd.stream.enable = True if args.enable == 'start' else False
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

DEFAULT_STREAM_ADDR = '127.0.0.1'
DEFAULT_STREAM_PORT = 7654      # for proto2bytes
DEFAULT_STREAM_TYPE = 'sample'
stream_parser = argparse.ArgumentParser(
    prog='stream',
    description='Control live stream behavior')
stream_parser.add_argument(
    '-f', '--force-daq-reset',
    default=False,
    action='store_true',
    help='[DANGEROUS] force DAQ module reset before streaming')
stream_parser.add_argument(
    '-t', '--type',
    choices=['sample', 'subsample'],
    default=DEFAULT_STREAM_TYPE,
    help='Type of packets to stream (default %s)' % DEFAULT_STREAM_TYPE)
stream_parser.add_argument(
    '-a', '--address',
    default=DEFAULT_STREAM_ADDR,
    help=('Address send packets to, default %s' %
          DEFAULT_STREAM_ADDR))
stream_parser.add_argument(
    '-p', '--port',
    default=DEFAULT_STREAM_PORT,
    help=('Port to send packets to, default %s' %
          DEFAULT_STREAM_PORT))
stream_parser.add_argument('enable',
                           choices=['start', 'stop'],
                           help='Start or stop streaming')

def nop_resp_filter(resps):
    return resps

COMMAND_HANDLING = {
    'err_regs': (err_regs,
                 no_arg_parser('err_regs', 'Print nonzero error registers'),
                 lambda resps: [r for r in resps if r.reg_io.val != 0]),
    'start': (start, no_arg_parser('start', 'Start acquiring to disk'),
              nop_resp_filter),
    'stop': (stop, no_arg_parser('stop', 'Stop acquiring to disk'),
             nop_resp_filter),
    'save_stream': (save_stream, save_stream_parser, nop_resp_filter),
    'stream': (stream, stream_parser, nop_resp_filter),
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
    handler, parser, rfilter = COMMAND_HANDLING[cmd]
    cmds = handler(parser.parse_args(cmd_args))
    resps = do_control_cmds(cmds)
    if resps is None:
        print("Didn't get a response", file=sys.stderr)
        sys.exit(1)
    for resp in rfilter(resps):
        print(resp, end='')

if __name__ == '__main__':
    main()
