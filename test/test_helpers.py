"""Helper module for test cases.
"""

from contextlib import closing
from itertools import chain, count, takewhile
import os
import subprocess
import time
import unittest

import h5py
import numpy

import daemon_control

# Environment and other gunk
DAEMON_PATH = os.environ['TEST_DAEMON_PATH']
DNODE_IP = os.environ['TEST_DNODE_IP']
DO_IT_LIVE = bool(int(os.environ['TEST_DO_IT_LIVE']))
DUMMY_DNODE_PATH = os.environ['TEST_DUMMY_DNODE_PATH']
SAMPSTREAMER_PATH = 'sampstreamer'
PROTO2BYTES_PATH = 'proto2bytes'
PROTO2BYTES_DEFAULT_PORT = 7654
RAW_MAGIC = '\x5a'
SAMPLE_RATE_HZ = 30000

# For checking HDF5 files
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

def daemon_sub(*args, **kwargs):
    sub = subprocess.Popen([DAEMON_PATH,
                            '-N',
                            '-A', DNODE_IP] +
                           list(args),
                           **kwargs)
    return sub

def dummy_dnode_sub(*args, **kwargs):
    sub = subprocess.Popen([DUMMY_DNODE_PATH] + list(args), **kwargs)
    return sub

def sampstreamer_sub(*args, **kwargs):
    sub = subprocess.Popen([SAMPSTREAMER_PATH] + list(args), **kwargs)
    return sub

def proto2bytes_sub(*args, **kwargs):
    sub = subprocess.Popen([PROTO2BYTES_PATH] + list(args), **kwargs)
    return sub

def _log_subset_of(N):
    """Returns an iterator for (0, 1, 2, 4, ..., N)."""
    po2 = takewhile(lambda p: p < N, (2**i for i in count()))
    return chain([0], po2, [N])

class DaemonTest(unittest.TestCase):
    """Parent class for tests which need leafysd and/or other utilities.

    Provides setUp() and tearDown() methods that ensure the needed
    utilities etc. are available or running."""

    def __init__(self, methodName='runTest',
                 start_daemon=True,
                 daemon_args=[],
                 start_dnode=True,
                 dnode_args=[],
                 start_proto2bytes=False,
                 proto2bytes_args=[],
                 proto2bytes_popen_kwargs={},
                 start_sampstreamer=False,
                 sampstreamer_args=[],
                 wait_for_connect=True):
        self.longMessage = True
        super(DaemonTest, self).__init__(methodName=methodName)
        self.start_daemon = start_daemon
        self.daemon_args = daemon_args
        self.start_dnode = start_dnode
        self.dnode_args = dnode_args
        self.start_sampstreamer = start_sampstreamer
        self.sampstreamer_args = sampstreamer_args
        self.start_proto2bytes = start_proto2bytes
        self.proto2bytes_args = proto2bytes_args
        self.proto2bytes_popen_kwargs = proto2bytes_popen_kwargs
        self.wait_for_connect = wait_for_connect

    def setUp(self):

        # Start the subprocesses
        dn = open('/dev/null', 'rw+')
        self.dn = dn
        self.sub_kwargs = { 'stdin': dn, 'stdout': dn, 'stderr': dn }
        if self.start_daemon:
            self.daemon = daemon_sub(*self.daemon_args, **self.sub_kwargs)
        if self.start_dnode and not DO_IT_LIVE:
            self.dnode = dummy_dnode_sub(*self.dnode_args, **self.sub_kwargs)
        if self.start_sampstreamer and not DO_IT_LIVE:
            self.sampstreamer = sampstreamer_sub(*self.sampstreamer_args,
                                                 **self.sub_kwargs)
        if self.start_proto2bytes:
            p2bkw = dict(self.sub_kwargs)
            p2bkw.update(self.proto2bytes_popen_kwargs)
            self.proto2bytes = proto2bytes_sub(*self.proto2bytes_args, **p2bkw)

        cmds = [daemon_control.reg_read(daemon_control.MOD_CENTRAL,
                                        daemon_control.CENTRAL_STATE)]
        # Spin until the daemon comes up
        if self.start_daemon:
            resps = daemon_control.do_control_cmds(cmds, retry=True)
            if resps is None:
                self.bail()

        # Spin until the daemon and data node connect to each other
        if (self.wait_for_connect and self.start_daemon and
            (self.start_dnode or DO_IT_LIVE)):
            attempt = 0
            err_type = daemon_control.ControlResponse.ERR
            no_dnode_code = daemon_control.ControlResErr.NO_DNODE
            while attempt < 50:
                if (resps is not None and resps[0].type == err_type and
                    resps[0].err.code == no_dnode_code):
                    resps = daemon_control.do_control_cmds(cmds, retry=False)
                    time.sleep(1.0)
                    attempt += 1
                else:
                    break
            if (resps is None or
                resps[0].type == daemon_control.ControlResponse.ERR):
                self.bail()

    def bail(self):
        self.tearDown()
        raise IOError("can't start up/set up necessary processes")

    def tearDown(self):
        if self.start_dnode and not DO_IT_LIVE:
            self.dnode.terminate()
            self.dnode.wait()
        if self.start_daemon:
            self.daemon.terminate()
            self.daemon.wait()
        if self.start_sampstreamer and not DO_IT_LIVE:
            self.sampstreamer.terminate()
            self.sampstreamer.wait()
        if self.start_proto2bytes:
            self.proto2bytes.terminate()
            self.proto2bytes.wait()
        self.dn.close()

    def ensureDsetChunkOK(self, dset, start, end, start_idx=0):
        last_sidx = None
        for i in xrange(start, end):
            board_sample = dset[i]
            self.assertEqual(board_sample[SAMP_INDEX], start_idx + i,
                             msg=str(i))
            self.assertFalse(board_sample[PH_FLAGS] & PH_ERRFLAG,
                             msg=str(i))

    def ensureHDF5OK(self, hdf5_path, nsamples):
        """Open an HDF5 file and do a cursory check of what's inside."""
        h5f = h5py.File(hdf5_path)
        with closing(h5f) as h5f:
            self.assertIn(expected_dset_name, h5f)
            dset = h5f[expected_dset_name]
            # Ensure the datatype matches our expectations
            self.assertEqual(dset.dtype, expected_dtype)
            self.assertEqual(len(dset), nsamples)

            # If the file's empty, that's all.
            if nsamples == 0:
                return

            chunk_size = 25
            start_idx = dset[0][SAMP_INDEX]
            end_idx = start_idx + nsamples - 1
            if nsamples <= chunk_size:
                # If there aren't too many samples, check them all.
                self.ensureDsetChunkOK(dset, start_idx, start_idx + nsamples,
                                       start_idx)
            else:
                # Otherwise, check a log-size subset of the samples
                # (including endpoints). This saves time on large
                # files; h5py is too slow to check every sample.
                for i in _log_subset_of(nsamples):
                    if i + chunk_size >= nsamples:
                        idx0 = nsamples - chunk_size
                        idxN = nsamples
                    else:
                        idx0 = i
                        idxN = i + chunk_size

                    self.ensureDsetChunkOK(dset, idx0, idxN, start_idx)

    def getAcquireCommand(self, enable=True):
        cmd = daemon_control.ControlCommand()
        cmd.type = daemon_control.ControlCommand.ACQUIRE
        cmd.acquire.exp_cookie = 0xcafebabe12345678L
        cmd.acquire.enable = enable
        return cmd
