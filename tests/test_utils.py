import os
import sys
import errno
import socket
import select
import threading
try:
    import unittest2
except ImportError:
    if sys.version_info < (2, 7):
        raise
    import unittest as unittest2

import mock

from spamc import SpamC
from spamc.utils import load_backend, is_connected, can_use_kqueue

from _s import return_unix


class TestSpamCUtils(unittest2.TestCase):

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

    def test_is_connected(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(os.environ.get('SPAMD_SOCK', 'spamd.sock'))
        self.assertTrue(is_connected(sock))
        sock.close()

    def test_mock_is_connected_error(self):
        skt = mock.Mock()
        skt.fileno.side_effect = socket.error('unknown error')
        with self.assertRaises(socket.error):
            is_connected(skt)
        skt.fileno.side_effect = socket.error(errno.EBADF, 'unknown error')
        self.assertFalse(is_connected(skt))

    @mock.patch('spamc.utils.select')
    def test_mock_is_connected_select(self, mock_select):
        retval = 13
        sock = mock.Mock()
        sock.fileno.return_value = retval
        mock_select.EPOLLOUT = 4
        setattr(mock_select, 'epoll', mock.Mock())
        mock_epoll = mock.Mock()
        mock_select.epoll.return_value = mock_epoll
        mock_epoll.poll.return_value = [(retval, 4)]
        self.assertTrue(is_connected(sock))
        delattr(mock_select, 'epoll')
        setattr(mock_select, 'poll', mock.Mock())
        mock_poll = mock.Mock()
        mock_select.poll.return_value = mock_poll
        mock_poll.poll.return_value = [(retval, 4)]
        self.assertTrue(is_connected(sock))

    @mock.patch('spamc.utils.select')
    def test_mock_is_connected_select_error(self, mock_select):
        retval = 13
        sock = mock.Mock()
        sock.fileno.return_value = retval
        mock_select.EPOLLOUT = 4
        setattr(mock_select, 'epoll', mock.Mock())
        mock_epoll = mock.Mock()
        mock_select.epoll.return_value = mock_epoll
        mock_epoll.poll.side_effect = ValueError('xx')
        self.assertFalse(is_connected(sock))
        mock_epoll.poll.side_effect = IOError('xxx')
        self.assertFalse(is_connected(sock))

    @mock.patch('spamc.utils.select')
    def test_mock_is_connected_select_unreg(self, mock_select):
        retval = 13
        sock = mock.Mock()
        sock.fileno.return_value = retval
        mock_select.EPOLLOUT = 4
        setattr(mock_select, 'epoll', mock.Mock())
        mock_epoll = mock.Mock()
        mock_select.epoll.return_value = mock_epoll
        mock_epoll.poll.return_value = [(20, 4)]
        mock_epoll.unregister.called_once_with(retval)

    # @mock.patch('spamc.utils.platform')
    # @mock.patch('spamc.utils.select')
    # def test_mock_is_connected_kqueue(self, mock_select, mock_platform):
    #     retval = 13
    #     delattr(mock_select, 'poll')
    #     delattr(mock_select, 'epoll')
    #     mock_event = mock.Mock()
    #     setattr(mock_event, 'ident', retval)
    #     setattr(mock_event, 'flags', 0)
    #     mock_kqueue = mock.Mock()
    #     mock_kqueue.return_value.control.return_value = [
    #         mock_event,
    #         mock_event
    #     ]
    #     setattr(mock_select, 'kqueue', mock_kqueue)
    #     mock_platform.system.return_value = 'Linux'
    #     # mock_platform.mac_ver.return_value = ('10.8',)
    #     sock = mock.Mock()
    #     sock.fileno.return_value = retval
    #     self.assertTrue(is_connected(sock))

    def test_load_module(self):
        mod = load_backend('thread')
        self.assertTrue(hasattr(mod, 'Socket'))

    def test_load_doted_module(self):
        self.assertRaises(ImportError, load_backend, 'socket.socket')

    def test_no_exist_module(self):
        self.assertRaises(ImportError, load_backend, 'axzssa22')

    @mock.patch('spamc.utils.platform')
    @mock.patch('spamc.utils.select', spec=select)
    def test_can_use_kqueue(self, mock_select, mock_platform):
        delattr(mock_select, 'kqueue')
        self.assertFalse(can_use_kqueue())
        setattr(mock_select, 'kqueue', True)
        self.assertTrue(can_use_kqueue())
        mock_platform.system.return_value = 'Darwin'
        mock_platform.mac_ver.return_value = ('10.6',)
        self.assertFalse(can_use_kqueue())
        mock_platform.mac_ver.return_value = ('10.8',)
        self.assertTrue(can_use_kqueue())


if __name__ == '__main__':
    unittest2.main()
