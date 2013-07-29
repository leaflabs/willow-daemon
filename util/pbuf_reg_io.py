"""Helper module for doing register I/O through the daemon.

Example use as a module:

from pbuf_reg_io import *

commands = [reg_read(MOD_CENTRAL, CENTRAL_STATE),
            reg_read(2, 14),
            reg_write(MOD_UDP, UDP_ENABLE, 0)]

responses = do_reg_ios(commands)

for i, rsp in enumerate(responses):
    print 'Response %d:' % i
    print '  * module:', rsp.reg_io.module
    print '  * value in hex: 0x%x' % rsp.reg_io.val
    print '  * Stringification:'
    print str(rsp),
    print
"""

from __future__ import print_function

import contextlib
from os.path import abspath, basename, dirname, join
import socket
import struct
import sys

import google.protobuf.text_format

# Tack the directory containing the protobuf serializers/deserializes
# onto sys.path.
script_file = abspath(__file__)
pyproto_dir = join(dirname(script_file), '..', 'build', 'pyproto', 'proto')
sys.path.append(pyproto_dir)

# Pull everything in from the generated protobuf module, for convenience
from control_pb2 import *

def reg_read(module, register):
    """Create a protocol message for reading a register."""
    reg_io = RegisterIO()
    reg_io.module = module
    if module == MOD_ERR:
        reg_io.err = register
    elif module == MOD_CENTRAL:
        reg_io.central = register
    elif module == MOD_SATA:
        reg_io.sata = register
    elif module == MOD_DAQ:
        reg_io.daq = register
    elif module == MOD_UDP:
        reg_io.udp = register
    elif module == MOD_GPIO:
        reg_io.gpio = register
    return ControlCommand(type=ControlCommand.REG_IO, reg_io=reg_io)

def reg_write(module, register, value):
    """Create a protocol message for reading a register."""
    reg_io = RegisterIO()
    reg_io.module = module
    reg_io.val=value
    if module == MOD_ERR:
        reg_io.err = register
    elif module == MOD_CENTRAL:
        reg_io.central = register
    elif module == MOD_SATA:
        reg_io.sata = register
    elif module == MOD_DAQ:
        reg_io.daq = register
    elif module == MOD_UDP:
        reg_io.udp = register
    elif module == MOD_GPIO:
        reg_io.gpio = register
    return ControlCommand(type=ControlCommand.REG_IO, reg_io=reg_io)

def do_reg_ios(commands):
    # Connect to the daemon.
    sckt = socket.create_connection(('127.0.0.1', 1371))
    if not sckt:
        print("can't create daemon connection", file=sys.stderr)
        sys.exit(1)

    with contextlib.closing(sckt) as sckt:
        # Send each command, then wait for and get the response.
        responses = []
        for i, cmd in enumerate(commands):
            # Pack cmd into a protocol buffer.
            ser = cmd.SerializeToString()
            # Convert cmd's packed length to a network byte-order uint32, and
            # send that first.
            sckt.send(struct.pack('>l', len(ser)))
            # Then send packed cmd.
            sckt.send(ser)

            # Try to get the response's length as network byte-order uint32.
            resplen_net = sckt.recv(4)
            if len(resplen_net) == 4:
                # Response length received. Convert it from network to host
                # byte ordering.
                resplen = struct.unpack('>l', resplen_net)[0]
                # Receive the response protocol buffer.
                pbuf_resp = sckt.recv(resplen)
            else:
                # No response length was received. Maybe the socket was closed?
                pbuf_resp = None

            # If we got a response, append it to the list.
            if pbuf_resp:
                rsp = ControlResponse()
                rsp.ParseFromString(pbuf_resp)
                responses.append(rsp)
            else:
                print("Didn't get response for command", i, file=sys.stderr)
                None
        return responses
