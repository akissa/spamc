#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim: ai ts=4 sts=4 et sw=4
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
"""Example program using spamc"""
import os
import pprint

from ssl import PROTOCOL_TLSv1
from optparse import OptionParser

from spamc import SpamC


FILES = [dict(type='spam', name='sample-spam.txt'),
         dict(type='ham', name='sample-nonspam.txt')]


def runit():
    """run things"""
    parser = OptionParser()
    parser.add_option('-s', '--server',
                      help='The spamassassin spamd server to connect to',
                      dest='server',
                      type='str',
                      default='standalone.home.topdog-software.com')
    parser.add_option('-p', '--port',
                      help='The spamassassin spamd server port to connect to',
                      dest='port',
                      type='int',
                      default=783)
    parser.add_option('-u', '--unix-socket',
                      help='The spamassassin spamd unix socket to connect to',
                      dest='socket_path',
                      type='str')
    parser.add_option('-t', '--tls',
                      help='Use TLS',
                      dest='tls',
                      action='store_true',
                      default=False)
    parser.add_option('-z', '--use-zlib-compression',
                      help='Use Zlib compression',
                      dest='gzip',
                      action='store_true',
                      default=False)
    parser.add_option('-l', '--zlib-compression-level',
                      help='Zlib compression level',
                      dest='compress_level',
                      type='choice',
                      choices=[str(val) for val in range(0, 10)],
                      default=6)
    parser.add_option('-a', '--user',
                      help=('''Username of the user on whose behalf'''
                            '''this scan is being performed'''),
                      dest='user',
                      type='str',
                      default='exim')
    options, _ = parser.parse_args()
    sslopts = {}
    if options.tls:
        sslopts = dict(ssl_version=PROTOCOL_TLSv1)
    if options.socket_path and os.path.exists(options.socket_path):
        options.server = None
    client = SpamC(
        options.server,
        port=options.port,
        socket_file=options.socket_path,
        user=options.user,
        gzip=options.gzip,
        compress_level=int(options.compress_level),
        is_ssl=options.tls,
        **sslopts)
    pprint.pprint(client.ping())
    path = os.path.dirname(__file__)
    for test in FILES:
        filename = os.path.join(path, test['name'])
        print "File => %s" % filename
        fileobj = open(filename)
        print "=" * 10, "client.check()"
        pprint.pprint(client.check(fileobj))
        print "=" * 10, "client.symbols()"
        pprint.pprint(client.symbols(fileobj))
        print "=" * 10, "client.report()"
        pprint.pprint(client.report(fileobj))
        print "=" * 10, "client.report_ifspam()"
        pprint.pprint(client.report_ifspam(fileobj))
        print "=" * 10, "client.process()"
        pprint.pprint(client.process(fileobj))
        print "=" * 10, "client.headers()"
        pprint.pprint(client.headers(fileobj))
        print "=" * 10, "client.learn()"
        pprint.pprint(client.learn(fileobj, test['type']))
        print "=" * 10, "client.tell()"
        pprint.pprint(client.tell(fileobj, 'forget'))
        print "=" * 10, "client.revoke()"
        pprint.pprint(client.revoke(fileobj))

if __name__ == "__main__":
    runit()
