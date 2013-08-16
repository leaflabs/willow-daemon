"""Tests against a race condition.

If a sample transfer finishes before the last transaction's reg I/O
result has been received, we need to wait to respond to the client or
otherwise react to the transfer until the result has been
processed. If we don't, the daemon gets confused.

Test that by reading 10 samples, which under normal conditions takes
considerably less time to finish than the last result.

"""

from __future__ import print_function

import unittest
import shutil
import sys
import tempfile
import time
import os

import test_helpers
from daemon_control import *

class TestFastSample(test_helpers.DaemonTest):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        super(TestFastSample, self).setUp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)
        super(TestFastSample, self).tearDown()

    def testFastSample(self):
        if not test_helpers.DO_IT_LIVE:
            raise unittest.SkipTest()

        cmd_en = self.getAcquireCommand(enable=True, start_sample=0)
        cmd_ds = self.getAcquireCommand(enable=False)

        # Start/stpo acquisition
        responses = do_control_cmds([cmd_en, cmd_ds])

        # Check the responses
        self.assertIsNotNone(responses)
        self.assertEqual(responses[0].type, ControlResponse.SUCCESS,
                         msg='\nenable response:\n' + str(responses[0]))
        self.assertEqual(responses[1].type, ControlResponse.SUCCESS,
                         msg='\ndisable response:\n' + str(responses[1]))

        # Get the data to disk
        store_path = os.path.join(self.tmpdir, "all_samples.h5")
        cs = ControlCommand(type=ControlCommand.STORE)
        cs.store.path = store_path
        cs.store.start_sample = 0
        cs.store.nsamples = 10
        cs.store.backend = STORE_HDF5
        responses = do_control_cmds([cs])
        self.assertIsNotNone(responses)
        resp = responses[0]
        msg = str(resp)
        self.assertEqual(resp.type, ControlResponse.STORE_FINISHED, msg=msg)
        rs = resp.store
        msg = '\nstore response:\n' + str(rs)
        self.assertEqual(rs.status, ControlResStore.DONE, msg=msg)
        self.assertEqual(rs.path, store_path, msg=msg)

        # Ensure the data looks ok
        self.ensureHDF5OK(rs.path, rs.nsamples)
