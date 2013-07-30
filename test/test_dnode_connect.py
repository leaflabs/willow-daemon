# Test that we can make a basic client/data node connection

import test_helpers

class TestDnodeConnect(test_helpers.DaemonTest):
    # DaemonTest will make the connection during setUp/tearDown time.
    def testThatsIt(self):
        pass
