# Test channel storage

from __future__ import print_function

from contextlib import closing
import os.path
import shutil
import tempfile

import test_helpers
from daemon_control import *

NSAMPLES = 30000

class TestChannelStorage(test_helpers.DaemonTest):

    def __init__(self, *args, **kwargs):
        kwargs['start_sampstreamer'] = True
        super(TestChannelStorage, self).__init__(*args, **kwargs)

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        super(TestChannelStorage, self).setUp()

    def tearDown(self):
        shutil.rmtree(self.tmpdir)
        super(TestChannelStorage, self).tearDown()

    def testSingleStorage(self):
        path = os.path.join(self.tmpdir, "singleStorage.h5")

        # Do the storage
        cmd = self.getStoreCmd(path, NSAMPLES)
        resps = do_control_cmds([cmd])

        # Make sure the response is well-formed and what we asked for.
        self.assertIsNotNone(resps)
        self.assertEqual(resps[0].type, ControlResponse.STORE_FINISHED,
                         msg='\nresponse:\n' + str(resps[0]))
        self.assertEqual(len(resps), 1)
        self.ensureStoreOK(resps[0].store, path, NSAMPLES)
        self.ensureHDF5OK(path, NSAMPLES)

    def testDoubleStorage(self):
        path = os.path.join(self.tmpdir, "doubleStorage.h5")

        # Do the storage twice, to ensure files get truncated properly
        cmds = [self.getStoreCmd(path, NSAMPLES)]
        sckt = get_daemon_control_sock()
        with closing(sckt) as sckt:
            resp1 = do_control_cmds(cmds, control_socket=sckt)
            resp2 = do_control_cmds(cmds, control_socket=sckt)

        # Make sure both results were good
        self.assertIsNotNone(resp1)
        self.assertIsNotNone(resp2)
        self.assertEqual(len(resp1), 1)
        self.assertEqual(len(resp2), 1)
        self.assertEqual(resp1[0].type, ControlResponse.STORE_FINISHED,
                         msg='\nresponse 1:\n' + str(resp1[0]))
        self.assertEqual(resp2[0].type, ControlResponse.STORE_FINISHED,
                         msg='\nresponse 2:\n' + str(resp2[0]))
        store1 = resp1[0].store
        store2 = resp2[0].store
        self.ensureStoreOK(store1, path, NSAMPLES)
        self.ensureStoreOK(store2, path, NSAMPLES)
        self.ensureHDF5OK(path, NSAMPLES)

    def getStoreCmd(self, path, nsamples, backend=STORE_HDF5):
        cmd = ControlCommand()
        cmd.type = ControlCommand.STORE
        cmd.store.path = path
        cmd.store.nsamples = nsamples
        cmd.store.backend = backend
        return cmd

    def ensureStoreOK(self, store, path, nsamples):
        msg = '\nstore:\n' + str(store)
        self.assertEqual(store.status, ControlResStore.DONE, msg=msg)
        self.assertEqual(store.path, path, msg=msg)
        self.assertEqual(store.nsamples, nsamples, msg=msg)
