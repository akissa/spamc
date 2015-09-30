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
regular expressions
"""
import re


BEGSP_RE = re.compile(r'^\s+\S+')
SPACE_RE = re.compile(r'\n([\s]*)')
RESPONSE_RE = re.compile(r'^SPAMD/(?:[0-9\.]+)\s(?P<code>[0-9]+)'
                         r'\s(?P<message>[0-9A-Z_]+)$')
SPAM_RE = re.compile(r'^Spam:\s(?P<isspam>True|False|Yes|No)\s;'
                     r'\s(?P<score>\-?[0-9\.]+)\s\/\s(?P<basescore>[0-9\.]+)')
DESC_RE = re.compile(r'^\s*([\S\s]*)\b\s*$')
PART_RE = re.compile(r'(?:([A-Z][A-Z0-9\_]+)\,?)')
RULE_RE = re.compile(r'^(\s|-)([0-9\.]+)\s+([A-Z0-9\_]+)\s+'
                     r'([^\s|-|\d]+.*(?:\n\s{2,}\S.*)?)$', re.MULTILINE)
