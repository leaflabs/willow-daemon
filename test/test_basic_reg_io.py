"""Test basic register I/O (reads/writes to registers)"""

import random
import time
import unittest

import test_helpers
from daemon_control import *

class TestBasicRegIO(test_helpers.DaemonTest):

    def testCentralState(self):
        cmd = reg_read(MOD_CENTRAL, CENTRAL_STATE)
        resps = do_control_cmds([cmd])
        self.assertIsNotNone(resps)
        self.assertEqual(resps[0].type, ControlResponse.REG_IO,
                         msg='\n' + str(resps[0]))
        rsp = resps[0].reg_io
        self.assertEqual(rsp.module, MOD_CENTRAL)
        self.assertEqual(rsp.central, CENTRAL_STATE)

    def testBasicRegIO(self):
        cookie_h = 0xaaaa5555
        cookie_l = 0xbbbbeeee
        cmds = [reg_write(MOD_CENTRAL, CENTRAL_COOKIE_H, cookie_h),
                reg_write(MOD_CENTRAL, CENTRAL_COOKIE_L, cookie_l)]
        responses = do_control_cmds(cmds)
        self.assertIsNotNone(responses)
        for i, rsp in enumerate(responses):
            self.assertEqual(rsp.type, ControlResponse.REG_IO,
                             msg='(resp %d); \n' % i + str(rsp))
        rsp_h, rsp_l = [r.reg_io for r in responses]
        self.assertEqual(rsp_h.module, MOD_CENTRAL)
        self.assertEqual(rsp_l.module, MOD_CENTRAL)
        self.assertEqual(rsp_h.central, CENTRAL_COOKIE_H)
        self.assertEqual(rsp_l.central, CENTRAL_COOKIE_L)
        self.assertEqual(rsp_h.val, cookie_h)
        self.assertEqual(rsp_l.val, cookie_l)
