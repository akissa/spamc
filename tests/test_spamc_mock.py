import sys
import socket
import threading
try:
    import unittest2
except ImportError:
    if sys.version_info < (2, 7):
        raise
    import unittest as unittest2

import mock

from spamc import SpamC
from spamc.exceptions import SpamCResponseError, SpamCError

from _s import return_tcp


class TestSpamCTCP(unittest2.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.using_sa = True
        cls.tcp_server = return_tcp(10060)
        t1 = threading.Thread(target=cls.tcp_server.serve_forever)
        t1.setDaemon(True)
        t1.start()
        cls.using_sa = False
        cls.spamc_tcp = SpamC(
            host='127.0.0.1',
            port=10060)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, 'tcp_server'):
            cls.tcp_server.shutdown()

    @mock.patch('spamc.client.get_response')
    def test_get_response(self, mock_get_response):
        mock_get_response.side_effect = SpamCResponseError(
            'spamd unrecognized response:')
        self.assertRaises(SpamCResponseError, self.spamc_tcp.ping)

    def test_spamc_tcp_exp1(self):
        with mock.patch.object(SpamC, 'get_connection') as mock_conn:
            mock_conn.return_value.socket.return_value.makefile\
                .return_value.read.return_value = ''
            spamc_tcp = SpamC(
                host='127.0.0.1',
                port=10060)
            with self.assertRaises(SpamCResponseError):
                spamc_tcp.ping()
            mock_conn.return_value.socket.return_value.makefile\
                .return_value.read.assert_called_once_with()

    def test_spamc_tcp_exp2(self):
        with mock.patch.object(SpamC, 'get_connection') as mock_conn:
            mock_conn.return_value._s.close.side_effect = socket.error('xxxx')
            mock_conn.return_value.send.side_effect = socket.error('xxxx')
            spamc_tcp = SpamC(
                host='127.0.0.1',
                port=10060)
            with self.assertRaises(SpamCError):
                spamc_tcp.ping()

    def test_spamc_tcp_exp3(self):
        with mock.patch.object(SpamC, 'get_connection') as mock_conn:
            mock_conn.return_value._s = None
            mock_conn.return_value.send.side_effect = socket.error('xxxx')
            spamc_tcp = SpamC(
                host='127.0.0.1',
                port=10060)
            with self.assertRaises(SpamCError):
                spamc_tcp.ping()

    def test_spamc_headers_learn(arg):
        with mock.patch.object(SpamC, 'perform') as mock_perform:
            msg = 'xxxx'
            spamc_tcp = SpamC(
                host='127.0.0.1',
                port=10060)
            spamc_tcp.tell(msg, 'learn', 'ham')
            headers = {'Set': 'local', 'Message-class': 'ham'}
            mock_perform.assert_called_once_with('TELL', msg, headers)

    def test_spamc_headers_report(arg):
        with mock.patch.object(SpamC, 'perform') as mock_perform:
            msg = 'xxxx'
            spamc_tcp = SpamC(
                host='127.0.0.1',
                port=10060)
            spamc_tcp.tell(msg, 'report')
            headers = {'Message-class': 'spam', 'Set': 'local, remote'}
            mock_perform.assert_called_once_with('TELL', msg, headers)

if __name__ == '__main__':
    unittest2.main()
