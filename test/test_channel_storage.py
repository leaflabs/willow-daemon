# Test channel storage

from __future__ import print_function

from contextlib import closing
import os.path
import shutil
import tempfile
import unittest

import h5py
import numpy

import test_helpers
from daemon_control import *

PH_FLAGS = 0
SAMP_INDEX = 1
CHIP_LIVE = 2
SAMPLES = 3
expected_dset_name = 'wired-dataset'
expected_dtype = numpy.dtype([('ph_flags', '|u1'),
                              ('samp_index', '<u4'),
                              ('chip_live', '<u4'),
                              ('samples', '<u2', (1120,))])

PH_ERRFLAG = 0x80

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
        nsamples = 300

        # Do the storage
        cmd = self.getStoreCmd(path, nsamples)
        resps = do_control_cmds([cmd])

        # Make sure the response is well-formed and what we asked for.
        self.assertIsNotNone(resps)
        self.assertEqual(resps[0].type, ControlResponse.STORE_FINISHED,
                         msg='\nresponse:\n' + str(resps[0]))
        self.assertEqual(len(resps), 1)
        self.ensureStoreOK(resps[0].store, path, nsamples)
        self.ensureHDF5OK(path, nsamples)

    def testDoubleStorage(self):
        path = os.path.join(self.tmpdir, "doubleStorage.h5")
        nsamples = 300

        # Do the storage twice, to ensure files get truncated properly
        cmds = [self.getStoreCmd(path, nsamples)]
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
        self.ensureStoreOK(store1, path, nsamples)
        self.ensureStoreOK(store2, path, nsamples)
        self.ensureHDF5OK(path, nsamples)

    def getStoreCmd(self, path, nsamples, backend=STORE_HDF5):
        cmd = ControlCommand()
        cmd.type = ControlCommand.STORE
        cmd.store.path = path
        cmd.store.nsamples = nsamples
        cmd.store.backend = backend
        return cmd

    def ensureStoreOK(self, store, path, nsamples):
        self.assertEqual(store.status, ControlResStore.DONE)
        self.assertEqual(store.path, path)
        self.assertEqual(store.nsamples, nsamples)

    def ensureHDF5OK(self, hdf5_path, nsamples):
        """Open an HDF5 file and do a cursory check of what's inside."""
        h5f = h5py.File(hdf5_path)
        with closing(h5f) as h5f:
            self.assertIn(expected_dset_name, h5f)
            dset = h5f[expected_dset_name]
            # Ensure the datatype matches our expectations
            self.assertEqual(dset.dtype, expected_dtype)
            self.assertEqual(len(dset), nsamples)
            last_sidx = None
            for data in dset:
                # Ensure sample indices increment properly
                if last_sidx is not None:
                    self.assertEqual(last_sidx + 1, data[SAMP_INDEX])
                last_sidx = data[SAMP_INDEX]
                # Ensure error flags aren't set
                self.assertNotEqual(data[PH_FLAGS] & PH_ERRFLAG, PH_ERRFLAG)
