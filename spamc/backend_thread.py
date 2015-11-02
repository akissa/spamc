"""
spamc: thread backend
"""
# pylint: disable=unused-import,invalid-name
# import select
import time
import socket

# Select = select.select
Socket = socket.socket
sleep = time.sleep
