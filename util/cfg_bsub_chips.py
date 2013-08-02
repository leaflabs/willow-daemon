#!/usr/bin/env python

import sys

from daemon_control import *

def set_channel_list(chip_chan_lst):
    cmds = []
    for i, chipchan in enumerate(chip_chan_lst):
        chip, chan = chipchan
        cmds.append(reg_write(MOD_DAQ, DAQ_SUBSAMP_CHIP0 + i,
                              chip << 8 | chan))
    return do_control_cmds(cmds)

def main(args):
    if len(args) != 1:
        parser.error("one argument: channel index")
    chip = int(args[0])
    set_channel_list([(chip, chan) for chan in range(32)])

if __name__ == '__main__':
    main(sys.argv[1:])
