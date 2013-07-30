"""Helper module for test cases.
"""

import os
import subprocess
import time
import unittest

import daemon_control

def daemon_sub(*args, **kwargs):
    sub = subprocess.Popen([os.environ['TEST_DAEMON_PATH'], '-N'] + list(args),
                           **kwargs)
    return sub

def dummy_dnode_sub(*args, **kwargs):
    sub = subprocess.Popen([os.environ['TEST_DUMMY_DNODE_PATH']] + list(args),
                           **kwargs)
    return sub

def sampstreamer_sub(*args, **kwargs):
    sub = subprocess.Popen(['sampstreamer'] + list(args), **kwargs)
    return sub

class DaemonTest(unittest.TestCase):
    """Parent class for tests which need leafysd and dummy-datanode running.

    Provides setUp() and tearDown() methods that ensure this
    happens."""

    def __init__(self, methodName='runTest',
                 start_daemon=True, start_dnode=True,
                 start_sampstreamer=False):
        super(DaemonTest, self).__init__(methodName=methodName)
        self.start_daemon = start_daemon
        self.start_dnode = start_dnode
        self.start_sampstreamer = start_sampstreamer

    def setUp(self):

        # Start the subprocesses
        dn = open('/dev/null', 'rw+')
        self.dn = dn
        self.sub_kwargs = { 'stdin': dn, 'stdout': dn, 'stderr': dn }
        if self.start_daemon:
            self.daemon = daemon_sub(**self.sub_kwargs)
        if self.start_dnode:
            self.dnode = dummy_dnode_sub(**self.sub_kwargs)
        if self.start_sampstreamer:
            self.sampstreamer = sampstreamer_sub(**self.sub_kwargs)

        cmds = [daemon_control.reg_read(daemon_control.MOD_CENTRAL,
                                        daemon_control.CENTRAL_STATE)]
        # Spin until the daemon comes up
        if self.start_daemon:
            resps = daemon_control.do_control_cmds(cmds, retry=True)
            if resps is None:
                self.bail()
        # Spin until the daemon and data node connect to each other
        if self.start_daemon and self.start_dnode:
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
        raise IOError("can't start up necessary processes")

    def tearDown(self):
        if self.start_dnode:
            self.dnode.terminate()
            self.dnode.wait()
        if self.start_daemon:
            self.daemon.terminate()
            self.daemon.wait()
        if self.start_sampstreamer:
            self.sampstreamer.terminate()
            self.sampstreamer.wait()
        self.dn.close()
