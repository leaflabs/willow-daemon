from __future__ import print_function

import unittest
import shutil
import sys
import tempfile
import time
import os

import test_helpers
from daemon_control import *

SLEEP_TIME_SEC = 60. * 0.2

class TestAcquire(test_helpers.DaemonTest):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        super(TestAcquire, self).setUp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)
        super(TestAcquire, self).tearDown()

    def do_testAcquire(self, start_sample):
        if not test_helpers.DO_IT_LIVE:
            raise unittest.SkipTest()

        cmd = self.getAcquireCommand(enable=True, start_sample=start_sample,
                                     exp_cookie=start_sample)

        # Start acquisition
        responses = do_control_cmds([cmd])
        self.assertIsNotNone(responses)
        resp = responses[0]
        self.assertEqual(resp.type, ControlResponse.SUCCESS,
                         msg='\nenable response:\n' + str(resp))

        # Run for a while
        print('Sleeping for', SLEEP_TIME_SEC / 60.,
              'minutes while data is being acquired',
              file=sys.stderr)
        time.sleep(SLEEP_TIME_SEC)

        # Stop acquisition
        cmd.acquire.enable = False
        responses = do_control_cmds([cmd])
        self.assertIsNotNone(responses)
        resp = responses[0]
        self.assertEqual(resp.type, ControlResponse.SUCCESS,
                         msg='\ndisable response:\n' + str(resp))

        # Get the data to disk
        store_path = os.path.join(self.tmpdir, "all_samples.h5")
        cs = ControlCommand(type=ControlCommand.STORE)
        cs.store.path = store_path
        cs.store.start_sample = start_sample
        cs.store.backend = STORE_HDF5
        responses = do_control_cmds([cs])
        self.assertIsNotNone(responses)
        resp = responses[0]
        self.assertEqual(resp.type, ControlResponse.STORE_FINISHED)
        rs = resp.store
        msg = '\nstore response:\n' + str(rs)
        self.assertEqual(rs.status, ControlResStore.DONE, msg=msg)
        self.assertEqual(rs.path, store_path)
        min_nsamples_expected = SLEEP_TIME_SEC * test_helpers.SAMPLE_RATE_HZ
        fudge_factor = 0.95
        self.assertTrue(rs.nsamples > fudge_factor * min_nsamples_expected)

        # Ensure the data looks ok
        self.ensureHDF5OK(rs.path, rs.nsamples, exp_cookie=start_sample)

    def testAcquire0(self):
        self.do_testAcquire(0)

    def testAcquire1920(self):
        self.do_testAcquire(1920)

    def testAcquire192000(self):
        self.do_testAcquire(192000)
