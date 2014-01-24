"""Tests acquisition very quickly (compared to test_acquire): ACQUIRE to disk,
sleep, stop, send and check samples.

The existance of this file (almost line-for-line copy of test_acquire) is an
ugly hack, but has a negligable impact on full test run times and is very
helpful as a quick fail-fast system test (eg, with fresh bitfiles or strange
network configurations).
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

SLEEP_TIME_SEC = 1.0

class TestShortAcquire(test_helpers.DaemonTest):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        super(TestShortAcquire, self).setUp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)
        super(TestShortAcquire, self).tearDown()

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
        print('Sleeping', SLEEP_TIME_SEC, 'seconds while acquiring... ',
              end='', file=sys.stderr)
        sys.stderr.flush()
        time.sleep(SLEEP_TIME_SEC)
        print('done.', file=sys.stderr)

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
        fudge_factor = 0.925
        self.assertTrue(rs.nsamples > fudge_factor * min_nsamples_expected)

        # Ensure the data looks ok
        self.ensureHDF5OK(rs.path, rs.nsamples, exp_cookie=start_sample)

    def testAcquire0(self):
        self.do_testAcquire(0)

