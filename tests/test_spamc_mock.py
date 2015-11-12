import sys
import threading
try:
    import unittest2
except ImportError:
    if sys.version_info < (2, 7):
        raise
    import unittest as unittest2

import mock

from spamc import SpamC
from spamc.exceptions import SpamCResponseError

from _s import return_tcp


class TestSpamCTCP(unittest2.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.using_sa = True
        cls.tcp_server = return_tcp(10050)
        t1 = threading.Thread(target=cls.tcp_server.serve_forever)
        t1.setDaemon(True)
        t1.start()
        cls.using_sa = False
        cls.spamc_tcp = SpamC(
            host='127.0.0.1',
            port=10050)

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
                port=10050)
            with self.assertRaises(SpamCResponseError):
                spamc_tcp.ping()
            mock_conn.return_value.socket.return_value.makefile\
                .return_value.read.assert_called_once_with()

if __name__ == '__main__':
    unittest2.main()
