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

Copyright 2015, Andrew Colin Kissa
Licensed under AGPLv3+
"""
import os
import socket

from mimetools import Message
from cStringIO import StringIO
from SocketServer import StreamRequestHandler, ThreadingTCPServer, \
    ThreadingUnixStreamServer


ThreadingTCPServer.allow_reuse_address = True

REPORT_TMPL = """Spam detection software, running on the system "localhost",
has identified this incoming email as possible spam.  The original
message has been attached to this so you can view it or label
similar future email.  If you have any questions, see
the administrator of that system for details.

Content preview:  This is the GTUBE, the Generic Test for Unsolicited Bulk
Email
   If your spam filter supports it, the GTUBE provides a test by which you can
   verify that the filter is installed correctly and is detecting incoming
   spam.
   You can send yourself a test mail containing the following string of
   characters (in upper case and with no white spaces and line breaks): [...]

Content analysis details:   (15.0 points, 5.0 required)

 pts rule name              description
---- ---------------------- --------------------------------------------------
-2.00 BAYES_00                  Bayes spam probability is 0 to 1%
 0.79 RDNS_NONE                  Delivered by a host with no rDNS
 0.50 KAM_LAZY_DOMAIN_SECURITY   Sender doesn't have anti-forgery methods
"""


class TestSpamdHandler(StreamRequestHandler):

    MessageClass = Message
    default_request_version = "SPAMD/1.0"

    def do_PING(self):
        """Emulate PING"""
        self.wfile.write("SPAMD/1.5 0 PONG\r\n")

    def do_TELL(self):
        """Emulate TELL"""
        self.wfile.write("SPAMD/1.5 0 EX_OK\r\n")
        didset = self.headers.get('Set')
        if didset:
            self.wfile.write("DidSet: True\r\n")
        didremove = self.headers.get('Remove')
        if didremove:
            self.wfile.write("DidRemove: True\r\n")
        self.wfile.write("\r\n\r\n")
        self.close_connection = 1

    def do_HEADERS(self):
        """Emulate HEADERS"""
        headers = []
        for header in self.headers:
            headers.append("%s: %s" % (header, self.headers[header]))
        # content = '\r\n'.join(headers)
        content_length = int(self.headers.get('Content-length', 0))
        body = self.rfile.read(content_length)
        parts, = body.split('\r\n\r\n')
        _headers = self.MessageClass(StringIO(parts))
        self.wfile.write("SPAMD/1.5 0 EX_OK\r\n")
        self.wfile.write("Spam: True ; 15 / 5\r\n")
        if self.request_version >= (1, 3):
            self.wfile.write("Content-length: %d\r\n" % len(_headers))
        self.wfile.write("\r\n\r\n")
        self.wfile.write(_headers)
        self.close_connection = 1

    def do_PROCESS(self):
        """Emulate PROCESS"""
        content_length = int(self.headers.get('Content-length', 0))
        body = self.rfile.read(content_length)
        self.wfile.write("SPAMD/1.5 0 EX_OK\r\n")
        self.wfile.write("Spam: True ; 15 / 5\r\n")
        if self.request_version >= (1, 3):
            self.wfile.write(
                "Content-length: %d\r\n" % content_length)
        self.wfile.write("\r\n\r\n")
        self.wfile.write(body)
        self.close_connection = 1

    def do_REPORT_IFSPAM(self):
        """Emulate REPORT_IFSPAM"""
        self.do_REPORT()

    def do_REPORT(self):
        """Emulate REPORT"""
        self.wfile.write("SPAMD/1.5 0 EX_OK\r\n")
        self.wfile.write("Spam: True ; 15 / 5\r\n")
        if self.request_version >= (1, 3):
            self.wfile.write(
                "Content-length: %d\r\n" % len(REPORT_TMPL))
        self.wfile.write("\r\n\r\n")
        self.wfile.write(REPORT_TMPL)
        self.close_connection = 1

    def do_SYMBOLS(self):
        """Emulate SYMBOLS"""
        rules = "BAYES_00,RDNS_NONE,KAM_LAZY_DOMAIN_SECURITY"
        self.wfile.write("SPAMD/1.5 0 EX_OK\r\n")
        self.wfile.write("Spam: True ; 15 / 5\r\n")
        if self.request_version >= (1, 3):
            self.wfile.write("Content-length: %d\r\n" % len(rules))
        self.wfile.write("\r\n\r\n")
        self.wfile.write(rules)
        if self.request_version < (1, 3):
            self.wfile.write("\r\n")
        self.close_connection = 1

    def do_CHECK(self):
        """Emulate CHECK"""
        self.wfile.write("SPAMD/1.5 0 EX_OK\r\n")
        self.wfile.write("Spam: True ; 15 / 5\r\n")
        self.wfile.write("\r\n\r\n")
        self.close_connection = 1

    def send_error(self, msg):
        """Send Error response"""
        self.wfile.write("SPAMD/1.0 EX_PROTOCOL Bad header line: %s\r\n" % msg)

    def parse_request(self):
        """Parse the request"""
        self.command = None
        self.request_version = version = self.default_request_version
        self.close_connection = 1
        requestline = self.raw_requestline
        requestline = requestline.rstrip('\r\n')
        self.requestline = requestline
        words = requestline.split()

        if len(words) == 2:
            command, version = words
            if version[:6] != 'SPAMC/':
                self.send_error("Bad request version (%r)" % version)
                return False
            try:
                base_version_number = version.split('/', 1)[1]
                version_number = base_version_number.split(".")
                if len(version_number) != 2:
                    raise ValueError

                version_number = int(version_number[0]), int(version_number[1])
            except (ValueError, IndexError):
                self.send_error("Bad request version (%r)" % version)
                return False
            if version_number >= (1, 6):
                self.send_error(
                    "Invalid HTTP Version (%s)" % base_version_number)
                return False
        elif not words:
            return False
        else:
            self.send_error("Bad request syntax (%r)" % requestline)
            return False
        self.command, self.request_version = command, version
        self.headers = self.MessageClass(self.rfile, 0)
        return True

    def handle_one_request(self):
        """Handle a request"""
        try:
            self.raw_requestline = self.rfile.readline(65537)
            if len(self.raw_requestline) > 65536:
                self.requestline = ''
                self.request_version = ''
                self.command = ''
                self.send_error("Invalid request")
                return

            if not self.raw_requestline:
                self.close_connection = 1
                return

            if not self.parse_request():
                return

            mname = 'do_' + self.command
            if not hasattr(self, mname):
                self.send_error("Unsupported method (%r)" % self.command)
                return

            method = getattr(self, mname)
            method()
            self.wfile.flush()
        except socket.timeout:
            self.close_connection = 1
            return

    def handle(self):
        """Main handler"""
        self.close_connection = 1

        self.handle_one_request()
        while not self.close_connection:
            self.handle_one_request()


def return_tcp():
    """Return a tcp SPAMD server"""
    address = ('127.0.0.1', 10000)
    server = ThreadingTCPServer(address, TestSpamdHandler)
    return server


def return_unix():
    """Return a unix SPAMD server"""
    sock = 'spamd.sock'
    if os.path.exists(sock):
        os.remove(sock)
    server = ThreadingUnixStreamServer(sock, TestSpamdHandler)
    return server


def start_tcp():
    """Start a tcp SPAMD server"""
    server = return_tcp()
    server.serve_forever()


def start_unix():
    """Start a unix SPAMD server"""
    server = return_unix()
    server.serve_forever()


if __name__ == '__main__':
    start_unix()
