import test_helpers
from daemon_control import *

class AbstractTestStream(test_helpers.DaemonTest):

    # TODO: start proto2bytes; ensure it yields data
    # WISHLIST: different port for proto2bytes than default

    def __init__(self, *args, **kwargs):
        kwargs['start_sampstreamer'] = True
        if 'sampstreamer_args' not in kwargs:
            kwargs['sampstreamer_args'] = []
        super(AbstractTestStream, self).__init__(*args, **kwargs)

    def do_test(self, sample_type):
        dst_port = test_helpers.PROTO2BYTES_DEFAULT_PORT
        cmd_stream = ControlCmdStream(dest_udp_addr4=0x7f000001,
                                      dest_udp_port=dst_port,
                                      enable=True,
                                      sample_type=sample_type)
        cmd = ControlCommand(type=ControlCommand.STREAM,
                             stream=cmd_stream)
        resps = do_control_cmds([cmd])
        self.assertIsNotNone(resps)
        resp = resps[0]
        self.assertEqual(resp.type, ControlResponse.SUCCESS,
                         msg='\nenable resp:\n' + str(resp))
        cmd.stream.enable = False
        resps = do_control_cmds([cmd])
        self.assertIsNotNone(resps)
        resp = resps[0]
        self.assertEqual(resp.type, ControlResponse.SUCCESS,
                         msg='\ndisable resp:\n' + str(resp))

class TestSubStream(AbstractTestStream):
    """Test that board subsample stream enable/disable commands get
    SUCCESS responses."""

    def __init__(self, *args, **kwargs):
        kwargs['sampstreamer_args'] = ['-s']
        super(TestSubStream, self).__init__(*args, **kwargs)

    def testSubStream(self):
        self.do_test(BOARD_SUBSAMPLE)

class TestSmpStream(AbstractTestStream):
    """Test that board sample stream enable/disable commands get SUCCESS
    responses."""

    def testSmpStream(self):
        self.do_test(BOARD_SAMPLE)
