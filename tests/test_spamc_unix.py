import os
import sys
import threading
try:
    import unittest2
except ImportError:
    if sys.version_info < (2, 7):
        raise
    import unittest as unittest2

from mimetools import Message
from cStringIO import StringIO

from spamc import SpamC
from spamc.exceptions import SpamCError

from _s import return_unix


class TestSpamCUnix(unittest2.TestCase):

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
        path = os.path.dirname(os.path.dirname(__file__))
        cls.filename = os.path.join(path, 'examples', 'sample-spam.txt')

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, 'tcp_server'):
            cls.unix_server.shutdown()
        if os.path.exists('spamd.sock'):
            try:
                os.remove('spamd.sock')
            except OSError:
                pass

    def test_spamc_unix_no_conn(self):
        spamc_unix = SpamC(socket_file='no-exist-spamd.sock')
        self.assertRaises(SpamCError, spamc_unix.ping)

    def test_spamc_unix_invalid_action(self):
        with open(self.filename) as handle:
            self.assertRaises(SpamCError, self.spamc_unix.tell, handle, 'mojo')

    def test_spamc_unix_ping(self):
        result = self.spamc_unix.ping()
        self.assertIn('message', result)
        self.assertEqual('PONG', result['message'])

    def test_spamc_unix_check(self):
        with open(self.filename) as handle:
            result = self.spamc_unix.check(handle)
        self.assertIn('message', result)
        self.assertEqual('EX_OK', result['message'])
        if not self.using_sa:
            self.assertEqual(15.0, result['score'])

    def test_spamc_unix_symbols(self):
        with open(self.filename) as handle:
            result = self.spamc_unix.symbols(handle)
        self.assertIn('message', result)
        self.assertEqual('EX_OK', result['message'])
        if not self.using_sa:
            self.assertIn('BAYES_00', result['symbols'])

    def test_spamc_unix_report(self):
        with open(self.filename) as handle:
            result = self.spamc_unix.report(handle)
        self.assertIn('message', result)
        self.assertEqual('EX_OK', result['message'])
        if not self.using_sa:
            self.assertIn('BAYES_00', result['report'][0]['name'])

    def test_spamc_unix_report_ifspam(self):
        with open(self.filename) as handle:
            result = self.spamc_unix.report_ifspam(handle)
        self.assertIn('message', result)
        self.assertEqual('EX_OK', result['message'])
        if not self.using_sa:
            self.assertIn('BAYES_00', result['report'][0]['name'])

    def test_spamc_unix_process(self):
        with open(self.filename) as handle:
            result = self.spamc_unix.process(handle)
        self.assertIn('message', result)
        with open(self.filename) as headerhandle:
            headers1 = Message(headerhandle)
        headers2 = Message(StringIO(result['message']))
        self.assertEqual(
            headers1.get('Subject'),
            headers2.get('Subject')
        )

    def test_spamc_unix_headers(self):
        with open(self.filename) as handle:
            result = self.spamc_unix.headers(handle)
        self.assertIn('message', result)
        with open(self.filename) as headerhandle:
            headers = Message(headerhandle)
        org_subject = "Subject: %s" % headers.get('Subject')
        new_subject = "Subject: %s" % result['headers'].get('Subject')
        self.assertEqual(org_subject, new_subject)

    def test_spamc_unix_learn(self):
        with open(self.filename) as handle:
            result = self.spamc_unix.learn(handle, 'spam')
        self.assertIn('message', result)
        self.assertEqual('EX_OK', result['message'])
        if not self.using_sa:
            self.assertEqual(True, result['didset'])
            self.assertEqual(False, result['didremove'])

    def test_spamc_unix_tell(self):
        with open(self.filename) as handle:
            result = self.spamc_unix.tell(handle, 'forget')
        self.assertIn('message', result)
        self.assertEqual('EX_OK', result['message'])
        if not self.using_sa:
            self.assertEqual(False, result['didset'])
            self.assertEqual(True, result['didremove'])

    def test_spamc_unix_revoke(self):
        print self.spamc_unix.host
        with open(self.filename) as handle:
            result = self.spamc_unix.revoke(handle)
        self.assertIn('message', result)
        self.assertEqual('EX_OK', result['message'])
        if not self.using_sa:
            self.assertEqual(True, result['didset'])
            self.assertEqual(True, result['didremove'])

if __name__ == '__main__':
    unittest2.main()
