import sys
try:
    import unittest2
except ImportError:
    if sys.version_info < (2, 7):
        raise
    import unittest as unittest2

from spamc.utils import load_backend


class TestSpamCTCP(unittest2.TestCase):

    def test_load_module(self):
        mod = load_backend('thread')
        self.assertTrue(hasattr(mod, 'Socket'))

    def test_load_doted_module(self):
        self.assertRaises(ImportError, load_backend, 'socket.socket')

    def test_no_exist_module(self):
        self.assertRaises(ImportError, load_backend, 'axzssa22')
