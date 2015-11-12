"""
spamc: eventlet backend
"""
# pylint: disable=unused-import,invalid-name,no-member
# from eventlet.green import select
from eventlet import sleep
from eventlet.green import socket

Socket = socket.socket
# Select = select.select
assert sleep
