# Test basic register I/O with the dummy data node

import random
import time
import unittest

import test_helpers
from daemon_control import *

# FIXME: allow the environment to show logging output to stderr, for
# debugging tests

class TestBasicRegIO(unittest.TestCase):

    def setUp(self):
        dn = open('/dev/null', 'rw+')
        self.dn = dn
        self.sub_kwargs = { 'stdin': dn, 'stdout': dn, 'stderr': dn }
        self.daemon = test_helpers.daemon_sub(**self.sub_kwargs)
        self.dnode = test_helpers.dummy_dnode_sub(**self.sub_kwargs)

    def tearDown(self):
        self.daemon.terminate()
        self.dnode.terminate()
        self.dn.close()

    def testCentralState(self):
        cmd = reg_read(MOD_CENTRAL, CENTRAL_STATE)
        resps = do_control_cmds([cmd], retry=True)
        self.assertIsNotNone(resps)
        rsp = resps[0].reg_io
        self.assertEqual(rsp.module, MOD_CENTRAL)
        self.assertEqual(rsp.central, CENTRAL_STATE)

    def testBasicRegIO(self):
        cookie_h = 0xaaaa5555
        cookie_l = 0xbbbbeeee
        cmds = [reg_write(MOD_CENTRAL, CENTRAL_COOKIE_H, cookie_h),
                reg_write(MOD_CENTRAL, CENTRAL_COOKIE_L, cookie_l)]
        responses = do_control_cmds(cmds, retry=True)
        self.assertIsNotNone(responses)
        rsp_h, rsp_l = [r.reg_io for r in responses]
        self.assertEqual(rsp_h.module, MOD_CENTRAL)
        self.assertEqual(rsp_l.module, MOD_CENTRAL)
        self.assertEqual(rsp_h.central, CENTRAL_COOKIE_H)
        self.assertEqual(rsp_l.central, CENTRAL_COOKIE_L)
        self.assertEqual(rsp_h.val, cookie_h)
        self.assertEqual(rsp_l.val, cookie_l)
