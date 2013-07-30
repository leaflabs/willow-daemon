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

class DaemonDnodeTest(unittest.TestCase):
    """Parent class for tests which need leafysd and dummy-datanode running.

    Provides setUp() and tearDown() methods that ensure this
    happens."""

    def setUp(self):
        dn = open('/dev/null', 'rw+')
        self.dn = dn
        self.sub_kwargs = { 'stdin': dn, 'stdout': dn, 'stderr': dn }
        self.daemon = daemon_sub(**self.sub_kwargs)
        self.dnode = dummy_dnode_sub(**self.sub_kwargs)
        cmds = [daemon_control.reg_read(daemon_control.MOD_CENTRAL,
                                        daemon_control.CENTRAL_STATE)]
        # Spin until the daemon comes up
        resps = daemon_control.do_control_cmds(cmds, retry=True)
        if resps is None:
            self.bail()
        # Spin until the daemon and data node connect to each other
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
        raise IOError("can't connect daemon to dummy-datanode")

    def tearDown(self):
        self.daemon.terminate()
        self.dnode.terminate()
        self.daemon.wait()
        self.dnode.wait()
        self.dn.close()
