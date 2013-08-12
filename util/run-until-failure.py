#!/usr/bin/env python2.7

from __future__ import print_function
import sys
import time

from daemon_control import *

cmd = ControlCommand(type=ControlCommand.ACQUIRE)
cmd.acquire.exp_cookie = 0xdead0000f001000
cmd.acquire.enable = True
cmd.acquire.start_sample = 0

ping = reg_read(MOD_ERR, ERR_ERR0)

acq_res = do_control_cmds([cmd])
if acq_res is None:
    print("No response to acquire", file=sys.stderr)
elif acq_res[0].type != ControlResponse.SUCCESS:
    print("Failed to acquire:", str(acq_res[0]), file=sys.stderr)

start = time.time()
while True:
    ping_res = do_control_cmds([ping])
    if (ping_res is None or
        ping_res[0].type == ControlResponse.ERR):
        stop = time.time()
        diff = stop - start
        print("FAILED (err or no response) at time offset %d (%g minutes)" %
              (diff, diff / 60), file=sys.stderr)
        sys.exit(1)

    if ping_res[0].reg_io.val != 0:
        stop = time.time()
        diff = stop - start
        print("FAILED at time offset %d (%g minutes)" % (diff, diff / 60),
              file=sys.stderr)

        val = ping_res[0].reg_io.val
        print("nonzero error register response:", hex(val), file=sys.stderr)
        print(str(ping_res[0]), file=sys.stderr)
        print("other nonzero error registers:")
        for r in get_err_regs():
            print(r)
        sys.exit(1)
    else:
        print("OK:", time.time() - start)
    time.sleep(10)
