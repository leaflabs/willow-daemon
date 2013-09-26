#!/usr/bin/env python
"""
Copyright: (C) 2013 LeafLabs, LLC
License: MIT License
Author: bnewbold
Date: September 2013
Project: SNG Wired Leaf (SNG4)

This is essentially a port of the old packet_tool.py to work through the
daemon (instead of writing raw TCP packets).

It does not do any acquisition modes, HDF5 storage, or UDP capture; for that
use acquire.py and/or proto2bytes (which is the equivalent of udp_tool.py).

See the '-h' usage for more info.
"""

from __future__ import print_function
import argparse
import collections
import os.path
import sys
import time

from daemon_control import *

# map of module indexes
modules = {
    'error': 0,
    'central': 1,
    'sata': 2,
    'daq': 3,
    'udp': 4,
    'gpio': 5,
    'ext': 5,
}

# count of registers for each module (used for 'dump' command)
module_len = [
    1,  # error
    8,  # central
    20,  # sata
    14, # daq
    15, # udp
    5,  # gpio
]

# ========== Helpers =========== #
def ints(data):
    "Helper to split a 32bit int into a tuple of 4 bytes"
    return (((data >> 24) & 0xFF) % 256,
            ((data >> 16) & 0xFF) % 256,
            ((data >> 8) & 0xFF) % 256,
            (data & 0xFF))

def toint(data):
    "Helper to convert 4 bytes into a 32bit int"
    l = map(ord, data)
    return (l[0] << 24) + (l[1] << 16) + (l[2] << 8) + l[3]

def repr_data(val):
    "Helper to pretty print a tuple of 4 bytes"
    i = int(val)
    d = ints(i)
    h = " ".join("%.2x" % b for b in d).upper()
    return "%10d  | %s (%3d %3d %3d %3d)" % (i, h, d[0], d[1], d[2], d[3])

def read_request(module, addr):
    """
    Helper to execute a single register read transaction, in a blocking
    manner.
    """
    reply = do_control_cmd(reg_read(module, addr))
    if reply is None or reply.type != 255: # TODO: 255 == REG_IO
        raise Exception("%s\nNo reply! Is daemon running?" % reply)
    return reply.reg_io.val

def write_request(module, addr, data):
    """
    Helper to execute a single register write transaction, in a blocking
    manner.

    'data' should be 32bits as an integer
    """
    reply = do_control_cmd(reg_write(module, addr, data))
    if reply is None or reply.type != 255: # TODO: 255 == REG_IO
        raise Exception("%s\nNo reply! Is daemon running?" % reply)
    return reply.reg_io.val

def parse_module(raw):
    if raw in modules.keys():
        module = modules[raw]
    else:
        module = int(raw)
        if not module in modules.values():
            raise Exception("Invalid module index: %d" % module)
    return module

def parse_value(s):
    """Convert a variety of input strings to a (32bit) integer"""
    # try binary values
    if s.lower() in ["on", "true", "yes"]:
        return 1
    if s.lower() in ["off", "false", "no"]:
        return 0

    if s.startswith('0b'):
        # binary
        return int(s[2:], 2)
    if s.startswith('0x'):
        # hex
        return int(s[2:], 16)
    if len(s.split('.')) == 4:
        # ipv4 address?
        l = map(int, s.split('.'))
        return (l[0] << 24) + (l[1] << 16) + (l[2] << 8) + l[3]
    # fall back to int(); if this fails, an exception will be raised
    return int(s)

def set_channel_list(l):
    """
    Takes a list of 32 (chip, chan) tuples and tells to data node to return
    those channel pairings as the 32 "virtual channels" in live-streaming
    sub-sample packets.
    """
    for i in range(32):
        chip = l[i][0] & 0b00011111
        chan = l[i][1] & 0b00011111
        reg_write(modules['daq'], 128+i, (chip << 8) | chan)

# ========== Commands =========== #

def ping(delay_sec=0.5):
    start = 0
    diff = 0
    while True:
        sys.stdout.write("Ping... ")
        sys.stdout.flush()
        start = time.time()
        try:
            read_request(0, 0)
            diff = time.time() - start
            sys.stdout.write("Pong (%.3fms)\n" % (diff*1000.))
        except:
            sys.stdout.write("Failed.\n")
        sys.stdout.flush()
        time.sleep(delay_sec)

def blink(period=0.5, gpio_pin=0):
    index = int(gpio_pin) + 8
    if index >= 16:
        raise Exception("Invalid GPIO pin: %s" % gpio_pin)
    on_val = 0x0001 << index 
    off_val = 0x0000
    while True:
        write_request(5, 4, on_val)
        print("On.")
        time.sleep(period/2.0)
        write_request(5, 4, off_val)
        print("Off.")
        time.sleep(period/2.0)

def dump(module):
    module = parse_module(module)
    for k in modules.keys():
        if modules[k] == module:
            print("All registers for '%s' module:" % k)
    for addr in range(module_len[module]):
        reply_val = read_request(module, addr)
        print("Register value at %d, %d: \t%s" % (
            module, addr, repr_data(reply_val)))

def do_reg_read(module, addr):
    module = parse_module(module)
    reply_val = read_request(module, addr)
    print("Register value at %d, %d: \t%s" % (
        module, addr, repr_data(reply_val)))

def do_reg_write(module, addr, value):
    module = parse_module(module)
    reply_val = write_request(module, addr, parse_value(value))
    print("Written to %d, %d: \t%s" % (
        module, addr, repr_data(reply_val)))

def intan_write(intan_addr, value):
    module = modules['daq']
    addr = 5
    intan_addr = intan_addr & 0b00111111
    value = parse_value(value) & 0xFF
    cmd = (0x1 << 24) | \
          (0xFF << 16) | \
          ((0b10000000 | intan_addr) << 8) | \
          value
    print("CMD: %s" % hex(cmd))
    reply_val = write_request(module, addr, cmd)
    print("Written to %d, %d: \t%s" % (
        module, addr, repr_data(reply_val)))
    reply = write_request(module, addr, cmd)
    print("Written to %d, %d: \t%s" % (
        module, addr, repr_data(reply_val)))
    print("That means that register %d (zero-indexed) was set to %d (integer) "
        "for all attached Intan chips." % (intan_addr, value))
    print("(assuming that acquisition was running...)")

def config_subsamples(constant, number):
    l = []
    if constant == "chip":
        l = [(number, chan) for chan in range(32)]
    elif constant == "channel":
        l = [(chip, number) for chip in range(32)]
    else:
        raise Exception("Don't know how to hold constant '%s'" % constant)
    print("Setting sub-sample channels as:")
    print()
    print("\tindex\tchip\tchannel")
    for i in range(len(l)):
        print("\t%3d\t%3d\t%3d" % (i, l[i][0], l[i][1]))
    set_channel_list(l)
    print("Done.")
    

# ========== Script/Args =========== #
def main():
    parser = argparse.ArgumentParser(
        description="Low-level data node register manipulation tool")
    subparsers = parser.add_subparsers(title="commands")

    # commands with no arguments are instantiated tersely
    subparsers.add_parser('ping',
            help="continuously ping the data node",
            description="Continuously ping the data node. Prints latency as "
                        "it goes.")\
        .set_defaults(func=ping)
    subparsers.add_parser('blink',
            help="continuously blink an LED",
            description="Continuously toggles a GPIO line on the board, which "
                        "causes an orange LED to blink.")\
        .set_defaults(func=blink)

    parser_dump = subparsers.add_parser('dump',
        help="print all registers for a single module",
        description="Print all registers for a single module.")
    parser_dump.add_argument("module", type=str)
    parser_dump.set_defaults(func=dump)

    parser_read = subparsers.add_parser('read',
        help="read from a single register value",
        description="Read from a single register value.",)
    parser_read.add_argument("module", type=str)
    parser_read.add_argument("addr", type=int)
    parser_read.set_defaults(func=do_reg_read)

    parser_write = subparsers.add_parser('write',
        help="write to a single register value",
        description="Write to a single register value.")
    parser_write.add_argument("module", type=str)
    parser_write.add_argument("addr", type=int)
    parser_write.add_argument("value", type=str)
    parser_write.set_defaults(func=do_reg_write)

    parser_intan_write = subparsers.add_parser('intan_write',
        help="write to a single register on all Intan chips",
        description="Write to a single register on all Intan chips.")
    parser_intan_write.add_argument("intan_addr", type=int)
    parser_intan_write.add_argument("value", type=str)
    parser_intan_write.set_defaults(func=intan_write)

    parser_subsamples = subparsers.add_parser('subsamples',
        help="assign subsample channels by a chip or per-chip channels",
        description="In live sub-sample streaming mode, the 32 'virtual' "
                    "channels can each individually be configured to point "
                    "to any of the 1024 regular channels (32 channels for "
                    "each of 32 chips. This command will configure the "
                    "virtual channels by either holding the chip number "
                    "constant (and selecting all 32 channels for "
                    "that chip) or holding the channel number constant "
                    "(and selecting that channel across all 32 chips in "
                    "parallel).")
    parser_subsamples.add_argument("--constant",
        choices=['chip','channel'],
        required=True,
        help="what to hold constant")
    parser_subsamples.add_argument("number",
        type=int,
        help="the value for the index being held constant")
    parser_subsamples.set_defaults(func=config_subsamples)
   
    args = parser.parse_args()
    func_kwargs = args.__dict__.copy()
    func_kwargs.pop('func')
    args.func(**func_kwargs)

if __name__ == '__main__':
    main()

