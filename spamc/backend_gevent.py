"""
spamc: gevent backend
"""
# pylint: disable=unused-import,invalid-name
# from gevent import select
from gevent import sleep
from gevent import socket

Socket = socket.socket
# Select = select.select
assert sleep
