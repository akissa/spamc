import os
import socket
import threading
import unittest2

from spamc import SpamC
from spamc.utils import is_connected

from _s import return_unix


class TestSpamCTCP(unittest2.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.using_sa = True
        if os.environ.get('SPAMD_SOCK', None) is None:
            cls.unix_server = return_unix()
            t1 = threading.Thread(target=cls.unix_server.serve_forever)
            t1.setDaemon(True)
            t1.start()
            cls.using_sa = False
        cls.spamc_unix = SpamC(
            socket_file=os.environ.get('SPAMD_SOCK', 'spamd.sock'))

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, 'tcp_server'):
            cls.unix_server.shutdown()

    # def test_is_not_connected(self):
    #     sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    #     self.assertFalse(is_connected(sock))

    def test_is_connected(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(os.environ.get('SPAMD_SOCK', 'spamd.sock'))
        self.assertTrue(is_connected(sock))
        sock.close()
