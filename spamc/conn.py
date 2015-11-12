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
import socket

from zlib import compressobj

# from spamc.utils import is_connected

BLOCK_SIZE = 64
CHUNK_SIZE = 16 * 1024


class Connector(object):
    """Base class for our connectors"""
    def __init__(self):
        # pylint: disable=invalid-name
        self._s = None
        self._connected = False

    def __del__(self):
        "del"
        self.release()

    def release(self):
        """release"""
        if hasattr(self, '_connected') and self._connected:
            self.invalidate()

    # def is_connected(self):
    #     """Check connection status"""
    #     if self._connected:
    #         return is_connected(self._s)
    #     return False

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
        "close"
        self._s.close()
        self._connected = False

    def send(self, data):
        "send data"
        return self._s.sendall(data)

    # def recv(self, size=1024):
    #     "receive data"
    #     return self._s.recv(size)

    def sendfile(self, data, zlib_compress=None, compress_level=6):
        """Send data from a file object"""
        if hasattr(data, 'seek'):
            data.seek(0)

        chunk_size = CHUNK_SIZE

        if zlib_compress:
            chunk_size = BLOCK_SIZE
            compressor = compressobj(compress_level)

        while 1:
            binarydata = data.read(chunk_size)
            if binarydata == '':
                break
            if zlib_compress:
                binarydata = compressor.compress(binarydata)
                if not binarydata:
                    continue
            self.send(binarydata)

        if zlib_compress:
            remaining = compressor.flush()
            while remaining:
                binarydata = remaining[:BLOCK_SIZE]
                remaining = remaining[BLOCK_SIZE:]
                self.send(binarydata)


class SpamCUnixConnector(Connector):
    """UnixConnector"""

    def __init__(self, socket_file, backend_mod):
        # pylint: disable=invalid-name
        super(SpamCUnixConnector, self).__init__()
        self._s = backend_mod.Socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket_file = socket_file
        self._s.connect(self.socket_file)
        self.backend_mod = backend_mod
        self._connected = True


class SpamCTcpConnector(Connector):
    """SpamCTcpConnector"""

    def __init__(self, host, port, backend_mod, is_ssl=False, **ssl_args):
        # pylint: disable=invalid-name
        super(SpamCTcpConnector, self).__init__()
        self._s = backend_mod.Socket(socket.AF_INET, socket.SOCK_STREAM)
        self._s.connect((host, port))
        self.host = host
        self.port = port
        self.backend_mod = backend_mod
        self._connected = True
        if is_ssl:
            self._s = ssl.wrap_socket(self._s, **ssl_args)
        self.is_ssl = is_ssl
