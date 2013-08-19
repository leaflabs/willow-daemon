"""Test data forwarding in (raw, proto) x (bsamp, bsubsamp) formats.

ONLY TESTS THAT _SOME_ DATA ARE RECEIVED. DOES NOT TEST CONTIGUITY OF
SAMPLES, E.G."""

import fcntl
import os
import subprocess
import time

import test_helpers
from daemon_control import *

DATA_TIMEOUT_SEC = 1.0
DST_PORT = test_helpers.PROTO2BYTES_DEFAULT_PORT

def make_nonblocking(file_like):
    fd = file_like.fileno()
    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

class ProtoDataMixin(object):
    """Mixin for checking streaming packets in protobuf format."""

    def got_stream_data(self):
        # Assuming hasatter(self, 'proto2bytes') is lazy; I don't care.
        make_nonblocking(self.proto2bytes.stdout)
        try:
            return bool(self.proto2bytes.stdout.read(1))
        except IOError:
            return False
        else:
            return True

class RawDataMixin(object):
    """Mixin for checking streaming packets in raw format."""

    def raw_start(self):
        self.sckt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sckt.bind(('localhost', DST_PORT))
        make_nonblocking(self.sckt)

    def raw_stop(self):
        self.sckt.close()

    def got_stream_data(self):
        try:
            data, addr = self.sckt.recvfrom(4)
        except IOError:
            return False
        else:
            if data[0] != test_helpers.RAW_MAGIC[0]:
                return False
            return True

class AbstractTestForward(test_helpers.DaemonTest):
    """Parent class for test cases for forwarding packets."""

    def __init__(self, *args, **kwargs):
        kwargs['start_dnode'] = True
        kwargs['start_sampstreamer'] = not test_helpers.DO_IT_LIVE
        super(AbstractTestForward, self).__init__(*args, **kwargs)

    def do_test(self, sample_type):
        cmd_forward = ControlCmdForward(dest_udp_addr4=0x7f000001,
                                        dest_udp_port=DST_PORT,
                                        enable=True,
                                        sample_type=sample_type,
                                        force_daq_reset=True)
        cmd = ControlCommand(type=ControlCommand.FORWARD,
                             forward=cmd_forward)

        # Start stream forwarding.
        resps = do_control_cmds([cmd])
        self.assertIsNotNone(resps)
        resp = resps[0]
        self.assertEqual(resp.type, ControlResponse.SUCCESS,
                         msg='\nenable resp:\n' + str(resp))

        # Ensure we get data within a timeout period.
        start = time.time()
        got_data = False
        self.assertTrue(hasattr(self, 'got_stream_data'))
        while time.time() - start < DATA_TIMEOUT_SEC:
            if self.got_stream_data():
                got_data = True
                break
        self.assertTrue(got_data)

        # Stop the stream.
        cmd.forward.enable = False
        resps = do_control_cmds([cmd])
        self.assertIsNotNone(resps)
        resp = resps[0]
        self.assertEqual(resp.type, ControlResponse.SUCCESS,
                         msg='\ndisable resp:\n' + str(resp))

class AbstractTestSubForward(AbstractTestForward):
    """Parent class for board subsample forwarding test cases."""

    def __init__(self, *args, **kwargs):
        kwargs['sampstreamer_args'] = ['-s']
        super(AbstractTestSubForward, self).__init__(*args, **kwargs)

class TestProtoSubForward(ProtoDataMixin, AbstractTestSubForward):

    def __init__(self, *args, **kwargs):
        kwargs['start_proto2bytes'] = True
        kwargs['proto2bytes_args'] = ['-c', '0', '-s']
        kwargs['proto2bytes_popen_kwargs'] = { 'stdout' : subprocess.PIPE }
        super(TestProtoSubForward, self).__init__(*args, **kwargs)

    def testProtoSubForward(self):
        self.do_test(BOARD_SUBSAMPLE)

class TestRawSubForward(RawDataMixin, AbstractTestSubForward):

    def testRawSubForward(self):
        self.raw_start()
        try:
            self.do_test(BOARD_SUBSAMPLE_RAW)
        finally:
            self.raw_stop()

class TestProtoSmpForward(ProtoDataMixin, AbstractTestForward):

    def __init__(self, *args, **kwargs):
        kwargs['start_proto2bytes'] = True
        kwargs['proto2bytes_args'] = ['-M', '-c', '0', '-s']
        kwargs['proto2bytes_popen_kwargs'] = { 'stdout' : subprocess.PIPE }
        super(TestProtoSmpForward, self).__init__(*args, **kwargs)

    def testProtoSmpForward(self):
        self.do_test(BOARD_SAMPLE)

class TestRawSmpForward(RawDataMixin, AbstractTestForward):

    def testRawSmpForward(self):
        self.raw_start()
        try:
            self.do_test(BOARD_SAMPLE_RAW)
        finally:
            self.raw_stop()
