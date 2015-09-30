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
sessions
"""
from socketpool import ConnectionPool
from spamc.conn import SpamCTcpConnector, SpamCUnixConnector


# pylint: disable=invalid-name
_default_session = {}


def return_session(backend_name, **options):
    """Return session pool"""
    # pylint: disable=W0603
    global _default_session

    if options['host'] is None:
        connection = SpamCUnixConnector
    else:
        connection = SpamCTcpConnector

    del options['host']

    if not _default_session:
        _default_session = {}
        pool = ConnectionPool(factory=connection,
                              backend=backend_name, **options)
        _default_session[backend_name] = pool
    else:
        if backend_name not in _default_session:
            pool = ConnectionPool(factory=connection,
                                  backend=backend_name, **options)

            _default_session[backend_name] = pool
        else:
            pool = _default_session.get(backend_name)
    return pool


def set_session(backend_name, **options):
    """Set session pool"""
    # pylint: disable=W0603
    global _default_session

    if not _default_session:
        _default_session = {}

    if options['host'] is None:
        connection = SpamCUnixConnector
    else:
        connection = SpamCTcpConnector

    del options['host']

    if backend_name in _default_session:
        pool = _default_session.get(backend_name)
    else:
        pool = ConnectionPool(factory=connection,
                              backend=backend_name, **options)
        _default_session[backend_name] = pool
    return pool
