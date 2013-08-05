"""Helper module for test cases.
"""

import os
import subprocess
import time
import unittest

import daemon_control

DAEMON_PATH = os.environ['TEST_DAEMON_PATH']
DNODE_IP = os.environ['TEST_DNODE_IP']
DO_IT_LIVE = bool(int(os.environ['TEST_DO_IT_LIVE']))
DUMMY_DNODE_PATH = os.environ['TEST_DUMMY_DNODE_PATH']
SAMPSTREAMER_PATH = 'sampstreamer'
PROTO2BYTES_PATH = 'proto2bytes'
PROTO2BYTES_DEFAULT_PORT = 7654

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
    sub = subprocess.popen([PROTO2BYTES_PATH] + list(args), **kwargs)
    return sub

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
                 sampstreamer_args=[]):
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
        if self.start_daemon and (self.start_dnode or DO_IT_LIVE):
            while (resps is not None and
                   resps[0].type == daemon_control.ControlResponse.ERR and
                   resps[0].err.code == daemon_control.ControlResErr.NO_DNODE):
                resps = daemon_control.do_control_cmds(cmds)
                time.sleep(0.2)
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
