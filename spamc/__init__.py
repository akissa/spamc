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
from spamc.client import SpamC
from spamc.version import version_info, __version__


assert SpamC
assert version_info
