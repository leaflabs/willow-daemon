#!/usr/bin/env python
"""
This script is for monitoring DAQ-SATA write reliability over longer time spans
(5+ minutes).

It assumes that acquisition is running and outputs a continuous .csv-style
stream:

    <DAQ-SATA FIFO count>,<SATA write delay>,<board sample index>\n

This can be plotted in KST using the included .kst configuration like so:

    ./acquire.py start
    ./monitor_sata_write.py > monitor.log &
    kst2 monitor_sata_write.kst

You may need to "reload all data sources" in KST's GUI for the samples to start
live-updating. "kill %1" to kill the monitor_sata_write.py job.
"""

import sys
import time

from daemon_control import *

def print_feedback_state():
    # TODO: aliases instead of hardcoded
    cmd1 = reg_read(MOD_SATA, 19) # FIFO Count for Feedback
    cmd2 = reg_read(MOD_SATA, 18) # SATA Write Delay
    cmd3 = reg_read(MOD_DAQ, 3) # BSI
    cmd_replies = do_control_cmds([cmd1, cmd2, cmd3])
    assert cmd_replies is not None, "Couldn't connect to daemon/node"
    rep1, rep2, rep3 = cmd_replies
    print("%d,%d,%d" % (rep3.reg_io.val, rep1.reg_io.val, rep2.reg_io.val))
    sys.stdout.flush()

def main(args):
    while True:
        print_feedback_state()
        time.sleep(0.1)

if __name__ == '__main__':
    main(sys.argv[1:])
