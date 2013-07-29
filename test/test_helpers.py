"""Helper module for test cases.
"""

import os
import subprocess

def daemon_sub(*args, **kwargs):
    sub = subprocess.Popen([os.environ['TEST_DAEMON_PATH'], '-N'] + list(args),
                           **kwargs)
    return sub

def dummy_dnode_sub(*args, **kwargs):
    sub = subprocess.Popen([os.environ['TEST_DUMMY_DNODE_PATH']] + list(args),
                           **kwargs)
    return sub
