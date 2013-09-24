"""Tests live-streaming "shots" during an acquisition to disk.

ACQUIRE to disk, sleep, repeatedly save live samples to disk (sort of checking
samples made it to disk), then stop."""

from __future__ import print_function

import unittest
import shutil
import sys
import tempfile
import time
import os

import test_helpers
from daemon_control import *

SLEEP_TIME_SEC = 0.50

class TestShots(test_helpers.DaemonTest):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        super(TestShots, self).setUp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)
        super(TestShots, self).tearDown()

    def do_testShots(self, count):
        if not test_helpers.DO_IT_LIVE:
            raise unittest.SkipTest()

        store_path = os.path.join(self.tmpdir, "multishot.h5")
        start_cmd, shot_cmd, stop_cmd = self.getStoreCmds(store_path, 100)

        # Start acquisition
        responses = do_control_cmds([start_cmd])
        self.assertIsNotNone(responses)
        resp = responses[0]
        self.assertEqual(resp.type, ControlResponse.SUCCESS,
                         msg='\nenable response:\n' + str(resp))

        # Run for a while
        print('Sleeping', SLEEP_TIME_SEC, 'seconds...',
              end='', file=sys.stderr)
        sys.stderr.flush()
        time.sleep(SLEEP_TIME_SEC)
        print('done.', file=sys.stderr)

        for i in range(count):
            responses = do_control_cmds([shot_cmd])
            self.assertIsNotNone(responses)
            resp = responses[0]
            self.assertEqual(resp.type, ControlResponse.STORE_FINISHED)
            rs = resp.store
            msg = '\nstore response:\n' + str(rs)
            self.assertEqual(rs.status, ControlResStore.DONE, msg=msg)
            self.assertEqual(rs.path, store_path)
            # Ensure the data looks ok
            self.ensureHDF5OK(rs.path, rs.nsamples)

        # Stop acquisition
        responses = do_control_cmds([stop_cmd])
        self.assertIsNotNone(responses)
        resp = responses[0]
        self.assertEqual(resp.type, ControlResponse.SUCCESS,
                         msg='\ndisable response:\n' + str(resp))


    def testShots0(self):
        self.do_testShots(1)

    def testShots3(self):
        self.do_testShots(3)

