import time
import unittest

from daemon_control import *

import test_helpers

class TestDnodeTimeout(test_helpers.DaemonTest):

    def __init__(self, *args, **kwargs):
        kwargs['wait_for_connect'] = False
        if test_helpers.DO_IT_LIVE:
            kwargs['start_daemon'] = False
            kwargs['start_dnode'] = False
        else:
            kwargs['start_dnode'] = True
            kwargs['dnode_args'] = ['--never-reply']
        super(TestDnodeTimeout, self).__init__(*args, **kwargs)

    def testDnodeTimeout(self):
        if test_helpers.DO_IT_LIVE:
            raise unittest.SkipTest()
        # With the dummy datanode in never-reply mode, a register read
        # should lead to an error response.
        cmd = reg_read(MOD_CENTRAL, CENTRAL_STATE)
        while True:
            resps = do_control_cmds([cmd], retry=True, max_retries=1000)
            self.assertIsNotNone(resps)
            self.assertEqual(resps[0].type, ControlResponse.ERR)
            if resps[0].err.code == ControlResErr.NO_DNODE:
                time.sleep(1)
                continue
            else:
                break
        self.assertEqual(resps[0].err.code, ControlResErr.DNODE_DIED)

