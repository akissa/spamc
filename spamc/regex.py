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


SPACE_RE = re.compile(r'\n([\s]*)')
RESPONSE_RE = re.compile(r'^SPAMD/(?:[0-9\.]+)\s(?P<code>[0-9]+)'
r'\s(?P<message>[0-9A-Z_]+)$')
SPAM_RE = re.compile(r'^Spam:\s(?P<isspam>True|False|Yes|No)\s;'
r'\s(?P<score>[0-9\.]+)\s\/\s(?P<basescore>[0-9\.]+)')
DESC_RE = re.compile(r'^\s*([\S\s]*)\b\s*$')
PART_RE = re.compile(r'([A-Z0-9\_]+)\,')
# -0.0 NO_RELAYS              Informational: message was not relayed via SMTP
#  1.0 MISSING_HEADERS        Missing To: header
RULE_RE = re.compile(r'(\s|-)([0-9\.]+)\s+([A-Z0-9\_]+)\s+([^:]+)\:\s([^\s]+)')
MATCH1_RE = re.compile(r'((?:\s|-)(?:[0-9\.]+)\s(?:[A-Z0-9\_]+)'
r'\s(?:[^:]+)\:\s(?:[^\n]+))')
