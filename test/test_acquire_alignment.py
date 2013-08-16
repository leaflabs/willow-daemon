"""Test that the daemon refuses STORE commands with bad sample alignment."""

import test_helpers
from daemon_control import *

class TestAcquireAlignment(test_helpers.DaemonTest):

    def __init__(self, *args, **kwargs):
        super(TestAcquireAlignment, self).__init__(*args, **kwargs)

    def testAcquireAlignmentSucceed(self):
        cmd1920 = self.getAcquireCommand(start_sample=1920)
        msg1920 = str(cmd1920)

        resps = do_control_cmds([cmd1920])

        self.assertIsNotNone(resps)

        try:
            self.assertEqual(resps[0].type, ControlResponse.SUCCESS,
                             msg=msg1920)
        finally:
            if do_control_cmds([self.getAcquireCommand(enable=False)]) is None:
                print("****** CAN'T STOP ACQUISITION! *******")

    def testAcquireAlignmentFail(self):
        cmd1 = self.getAcquireCommand(start_sample=1)
        cmd1919 = self.getAcquireCommand(start_sample=1919)
        cmd1921 = self.getAcquireCommand(start_sample=1921)
        cmdHigh = self.getAcquireCommand(start_sample=0xFFFFFFFF-1)
        msg1 = str(cmd1)
        msg1919 = str(cmd1919)
        msg1921 = str(cmd1921)
        msgHigh = str(cmdHigh)
        cmds = [cmd1, cmd1919, cmd1921, cmdHigh]

        resps = do_control_cmds(cmds)

        self.assertIsNotNone(resps)
        self.assertEqual(len(resps), len(cmds))
        self.assertEqual(resps[0].type, ControlResponse.ERR, msg=msg1)
        self.assertEqual(resps[0].err.code, ControlResErr.C_VALUE, msg=msg1)
        self.assertEqual(resps[1].type, ControlResponse.ERR, msg=msg1919)
        self.assertEqual(resps[1].err.code, ControlResErr.C_VALUE, msg=msg1919)
        self.assertEqual(resps[2].type, ControlResponse.ERR, msg=msg1921)
        self.assertEqual(resps[2].err.code, ControlResErr.C_VALUE, msg=msg1921)
        self.assertEqual(resps[3].type, ControlResponse.ERR, msg=msgHigh)
        self.assertEqual(resps[3].err.code, ControlResErr.C_VALUE, msg=msgHigh)
