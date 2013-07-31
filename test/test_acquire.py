import unittest
import time

import test_helpers
from daemon_control import *

SLEEP_TIME_SEC = 1.0

class TestAcquire(test_helpers.DaemonTest):

    def testAcquire(self):
        if not test_helpers.DO_IT_LIVE:
            raise unittest.SkipTest()
        cmd = ControlCommand()
        cmd.type = ControlCommand.ACQUIRE
        cmd.acquire.exp_cookie = 0xcafebabe12340000L
        cmd.acquire.enable = True
        responses = do_control_cmds([cmd])
        self.assertIsNotNone(responses)
        resp = responses[0]
        self.assertEqual(resp.type, ControlResponse.SUCCESS,
                         msg='\nenable response:\n' + str(resp))

        time.sleep(SLEEP_TIME_SEC) # FIXME: sigh...

        cmd.acquire.enable = False
        responses = do_control_cmds([cmd])
        self.assertIsNotNone(responses)
        resp = responses[0]
        self.assertEqual(resp.type, ControlResponse.SUCCESS,
                         msg='\ndisable response:\n' + str(resp))
