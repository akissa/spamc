# -*- coding: utf-8 -*-
# vim: ai ts=4 sts=4 et sw=4
# spamc - Python spamassassin spamc client library
# Copyright (C) 2015  Andrew Colin Kissa <andrew@topdog.za.net>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
spamc: Python spamassassin spamc client library
connections
"""
import ssl
import time
import random
import socket

from socketpool.conn import TcpConnector, Connector

from spamc.utils import is_connected

CHUNK_SIZE = 16 * 1024


class SpamCTcpConnector(TcpConnector):
    """SpamCTcpConnector"""
    def __init__(self, host, port, backend_mod, pool=None,
            is_ssl=False, **ssl_args):
        super(SpamCTcpConnector, self).__init__(host, port, backend_mod,
            pool)
        if is_ssl:
            self._s = ssl.wrap_socket(self._s, **ssl_args)
        self.is_ssl = is_ssl

    def __del__(self):
        """override delete"""
        pass

    def handle_exception(self, exception):
        """Raise exceptions"""
        raise

    def socket(self):
        """return socket"""
        return self._s

    def close(self):
        """close conn"""
        if not self._s or not hasattr(self._s, "close"):
            return
        try:
            self._s.close()
        except BaseException:
            pass

    def invalidate(self):
        """invalidate"""
        self.close()
        self._connected = False
        self._life = -1

    def release(self, should_close=False):
        """release"""
        if self._pool is not None:
            if self._connected:
                if should_close:
                    self.invalidate()
                self._pool.release_connection(self)
            else:
                self._pool = None
        elif self._connected:
            self.invalidate()

    def send(self, data):
        """Send data"""
        return self._s.sendall(data)

    def sendfile(self, data):
        """Send data from a file object"""
        if hasattr(data, 'seek'):
            data.seek(0)

        while 1:
            binarydata = data.read(CHUNK_SIZE)
            if binarydata == '':
                break
            self.send(binarydata)


class SpamCUnixConnector(Connector):
    """UnixConnector"""
    def __init__(self, socket_file, backend_mod, pool=None):
        self._sock = backend_mod.Socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket_file = socket_file
        self._sock.connect(self.socket_file)
        self.backend_mod = backend_mod
        self._connected = True
        self._life = time.time() - random.randint(0, 10)
        self._pool = pool

    def __del__(self):
        """override"""
        pass

    def socket(self):
        "return socket"
        return self._sock

    def matches(self, **match_options):
        "matches"
        target_sock = match_options.get('socket_file')
        return target_sock == self.socket_file

    def is_connected(self):
        "is connected"
        if self._connected:
            return is_connected(self._sock)
        return False

    def handle_exception(self, exception):
        "handle exception"
        raise exception

    def get_lifetime(self):
        "get lifetime"
        return self._life

    def invalidate(self):
        "invalidate"
        self.close()
        self._connected = False
        self._life = -1

    def release(self, should_close=False):
        """release"""
        if self._pool is not None:
            if self._connected:
                if should_close:
                    self.invalidate()
                self._pool.release_connection(self)
            else:
                self._pool = None
        elif self._connected:
            self.invalidate()

    def send(self, data):
        """Send data"""
        return self._sock.sendall(data)

    def recv(self, size=1024):
        "recv"
        return self._sock.recv(size)

    def close(self):
        """close conn"""
        if not self._sock or not hasattr(self._sock, "close"):
            return
        try:
            self._sock.close()
        except BaseException:
            pass

    def sendfile(self, data):
        """Send data from a file object"""
        if hasattr(data, 'seek'):
            data.seek(0)

        while 1:
            binarydata = data.read(CHUNK_SIZE)
            if binarydata == '':
                break
            self.send(binarydata)
