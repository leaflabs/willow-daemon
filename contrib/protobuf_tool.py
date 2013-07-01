#!/usr/bin/env python
"""
Copyright: (C) 2013 LeafLabs, LLC
License: MIT License
Author: mbolivar
Date: June 2013
Project: SNG Wired Leaf (SNG4)
"""

from __future__ import print_function

from os.path import abspath, dirname, join
import socket
import struct
import sys

import google.protobuf.text_format

# Tack our protobuf ser/des directory onto sys.path
script_file = abspath(__file__)
pyproto_dir = join(dirname(script_file), 'build', 'pyproto', 'proto')
sys.path.append(pyproto_dir)

import data_pb2

PROTOBUF_RECV_PORT = 7654

def get_fake_pbuf():
     ## Make fake data node data
     barr = bytearray()
     # header
     barr += '\x5a\x00\x80\x00'
     # cookie
     for b in struct.pack('!Q', 31415926):
         barr += b
     # board id
     for b in struct.pack('!L', 555):
         barr += b
     # sample index
     for b in struct.pack('!L', 1234567):
         barr += b
     # chips alive
     barr += '\xff\xff\xff\xff'
     # chip/channel configuration
     for i in range(32):
         for b in struct.pack('!BB', i, 31 - i):
             barr += b
     # samples
     for i in range(32):
         samp_val = i * 32767 / 32
         for b in struct.pack('!h', samp_val):
             barr += b
     # gpio, dac cfg, dac
     for b in struct.pack('!hBB', 1122, 33, 44):
         barr += b
     return barr

def send_fake_data(srcport=5678, dstport=1370):
     # Send fake dnode data
     dn_sckt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
     dn_sckt.bind(('127.0.0.1', srcport))
     dn_sckt.sendto(get_fake_pbuf(), ('127.0.0.1', dstport))

def dump(c_sckt):
     samp = data_pb2.DnodeSample()
     while True:
         sys.stdout.write('.')
         # Get protobuf out
         data, addr = c_sckt.recvfrom(1024)

         # Pretty-print the data
         if not data:
             print('no data')
         else:
             samp.ParseFromString(data)
             google.protobuf.text_format.PrintMessage(samp, sys.stdout)

def chan_dump(c_sckt, chan):
     samp = data_pb2.DnodeSample()
     while True:
         # Get protobuf out
         data, addr = c_sckt.recvfrom(1024)

         # Pretty-print the data
         if not data:
             print('no data')
         else:
             samp.ParseFromString(data)
             print(samp.subsample.samples[chan])

def field_dump(c_sckt, field):
     samp = data_pb2.DnodeSample()
     while True:
         # Get protobuf out
         data, addr = c_sckt.recvfrom(1024)

         # Pretty-print the data
         if not data:
             print('no data')
         else:
             samp.ParseFromString(data)
             print(getattr(samp.subsample, field))

def check_bsi(c_sckt):
     samp = data_pb2.DnodeSample()
     bsi = 0
     last_bsi = 0
     while True:
         # Get protobuf out
         data, addr = c_sckt.recvfrom(1024)

         # Pretty-print the data
         if not data:
             print('no data')
         else:
             samp.ParseFromString(data)
             bsi = samp.subsample.samp_idx
             if bsi - last_bsi != 1:
                print("GAP: %d" % (bsi - last_bsi - 1))
             elif bsi % 30000 == 0:
                print("tick")
             last_bsi = bsi

if __name__ == '__main__':
     c_sckt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
     c_sckt.bind(('', PROTOBUF_RECV_PORT))
     if len(sys.argv) >= 2 and sys.argv[1] == '-s':
         send_fake_data()
     elif len(sys.argv) >= 2 and sys.argv[1] == 'check_bsi':
        check_bsi(c_sckt)
     elif len(sys.argv) >= 2 and sys.argv[1] == 'chan':
        chan_dump(c_sckt, int(sys.argv[2]))
     elif len(sys.argv) >= 2:
        field_dump(c_sckt, sys.argv[1])
     else:
        dump(c_sckt)
