import os

from spamc import SpamC

from g import HOST, PORT
# run_test_server('tcp')
# run_test_server('unix')


class Scan(object):

    def __init__(
        self,
        conntype='tcp',
        socket_file=None,
        host=None,
        port=None,
            filename=None):
        self.type = conntype
        self.socket_file = socket_file or os.path.join(
            os.path.dirname(os.path.dirname(__file__)), 'spamd.sock')
        if conntype == 'tcp':
            self.host = host or HOST
            self.port = port or PORT
        else:
            self.host = None
            self.port = None
        if filename is None:
            path = os.path.dirname(os.path.dirname(__file__))
            self.filename = os.path.join(path, 'examples', 'sample-spam.txt')
        else:
            self.filename = filename

    def __call__(self, func):
        def run():
            res = SpamC(
                host=self.host,
                port=self.port,
                socket_file=self.socket_file,
                user='exim')
            func(res, self.filename)
        run.func_name = func.func_name
        return run


def eq(a, b):
    """comments"""
    assert a == b, "%r != %r" % (a, b)


def ne(a, b):
    """comments"""
    assert a != b, "%r == %r" % (a, b)


def lt(a, b):
    """comments"""
    assert a < b, "%r >= %r" % (a, b)


def gt(a, b):
    """comments"""
    assert a > b, "%r <= %r" % (a, b)


def isin(a, b):
    """comments"""
    assert a in b, "%r is not in %r" % (a, b)


def isnotin(a, b):
    """comments"""
    assert a not in b, "%r is in %r" % (a, b)


def has(a, b):
    """comments"""
    assert hasattr(a, b), "%r has no attribute %r" % (a, b)


def hasnot(a, b):
    """comments"""
    assert not hasattr(a, b), "%r has an attribute %r" % (a, b)


def raises(exctype, func, *args, **kwargs):
    """comments"""
    try:
        func(*args, **kwargs)
    except exctype:
        pass
    else:
        func_name = getattr(func, "func_name", "<builtin_function>")
        raise AssertionError("Function %s did not raise %s" % (
            func_name, exctype.__name__))
