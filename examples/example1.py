from spamc import SpamC


client = SpamC('192.168.1.26', user='exim')
client.check('My Message as String')
# {'basescore': 5.0,
#  'code': 0,
#  'headers': [],
#  'isspam': True,
#  'message': 'EX_OK',
#  'report': [],
#  'score': 8.0,
#  'symbols': []}
client.symbols('My Message as String')
# {'basescore': 5.0,
#  'code': 0,
#  'headers': [],
#  'isspam': True,
#  'message': 'EX_OK',
#  'report': [],
#  'score': 8.0,
#  'symbols': ['EMPTY_MESSAGE',
#              'MISSING_DATE',
#              'MISSING_FROM',
#              'MISSING_HEADERS',
#              'MISSING_MID',
#              'MISSING_SUBJECT',
#              'NO_HEADERS_MESSAGE',
#              'NO_RECEIVED']}
client.report('My Message as String')
# {'basescore': 5.0,
#  'code': 0,
#  'headers': [],
#  'isspam': True,
#  'message': 'EX_OK',
#  'report': [],
#  'score': 8.0,
#  'symbols': []}
client.report_ifspam('My Message as String')
# {'basescore': 5.0,
#  'code': 0,
#  'headers': [],
#  'isspam': True,
#  'message': 'EX_OK',
#  'report': [],
#  'score': 8.0,
#  'symbols': []}
client.ping()
# {'basescore': 0.0,
#  'code': 0,
#  'headers': [],
#  'isspam': False,
#  'message': 'PONG',
#  'report': [],
#  'score': 0.0,
#  'symbols': []}
client.process('My Message as String')
# {'basescore': 5.0,
#  'code': 0,
#  'headers': [],
#  'isspam': True,
#  'message': 'Received: from localhost by standalone.home.topdog-software.com\twith SpamAssassin (version 3.4.1);\tSat, 26 Sep 2015 11:54:24 +0200X-Spam-Checker-Version: SpamAssassin 3.4.1 (2015-04-28) on\tstandalone.home.topdog-software.comX-Spam-Flag: YESX-Spam-Level: *******X-Spam-Status: Yes, score=8.0 required=5.0 tests=EMPTY_MESSAGE,MISSING_DATE,\tMISSING_FROM,MISSING_HEADERS,MISSING_MID,MISSING_SUBJECT,NO_HEADERS_MESSAGE,\tNO_RECEIVED,NO_RELAYS shortcircuit=no autolearn=no autolearn_force=no\tversion=3.4.1MIME-Version: 1.0Content-Type: multipart/mixed; boundary="----------=_56066B50.4983EE84"This is a multi-part message in MIME format.------------=_56066B50.4983EE84Content-Type: text/plain; charset=iso-8859-1Content-Disposition: inlineContent-Transfer-Encoding: 8bitSpam detection software, running on the system "standalone.home.topdog-software.com",has identified this incoming email as possible spam.  The originalmessage has been attached to this so you can view it or labelsimilar future email.  If you have any questions, seethe administrator of that system for details.Content preview:  [...] Content analysis details:   (8.0 points, 5.0 required) pts rule name              description---- ---------------------- ---------------------------------------------------0.0 NO_RELAYS              Informational: message was not relayed via SMTP 1.0 MISSING_HEADERS        Missing To: header 0.5 MISSING_MID            Missing Message-Id: header 1.8 MISSING_SUBJECT        Missing Subject: header 1.0 MISSING_FROM           Missing From: header 1.4 MISSING_DATE           Missing Date: header 2.3 EMPTY_MESSAGE          Message appears to have no textual parts and no                            Subject: text-0.0 NO_RECEIVED            Informational: message has no Received headers 0.0 NO_HEADERS_MESSAGE     Message appears to be missing most RFC-822 headers------------=_56066B50.4983EE84Content-Type: message/rfc822; x-spam-type=originalContent-Description: original message before SpamAssassinContent-Disposition: inlineContent-Transfer-Encoding: 8bitMy Message as String------------=_56066B50.4983EE84--\r\n',
#  'report': [],
#  'score': 8.0,
#  'symbols': []}
client.headers('My Message as String')
# {'basescore': 5.0,
#  'code': 0,
#  'headers': ['Received: from localhost by standalone.home.topdog-software.com\twith SpamAssassin (version 3.4.1);\tSat, 26 Sep 2015 11:55:14 +0200',
#              'X-Spam-Checker-Version: SpamAssassin 3.4.1 (2015-04-28) on\tstandalone.home.topdog-software.com',
#              'X-Spam-Flag: YES',
#              'X-Spam-Level: *******',
#              'X-Spam-Status: Yes, score=8.0 required=5.0 tests=EMPTY_MESSAGE,MISSING_DATE,\tMISSING_FROM,MISSING_HEADERS,MISSING_MID,MISSING_SUBJECT,NO_HEADERS_MESSAGE,\tNO_RECEIVED,NO_RELAYS shortcircuit=no autolearn=no autolearn_force=no\tversion=3.4.1',
#              'MIME-Version: 1.0',
#              'Content-Type: multipart/mixed; boundary="----------=_56066B82.30208A64"',
#              '',
#              ''],
#  'isspam': True,
#  'message': 'EX_OK',
#  'report': [],
#  'score': 8.0,
#  'symbols': []}
client.learn('My Message as String', 'spam')
# {'basescore': 0.0,
#  'code': 0,
#  'didremove': False,
#  'didset': True,
#  'headers': [],
#  'isspam': False,
#  'message': 'EX_OK',
#  'report': [],
#  'score': 0.0,
#  'symbols': []}
client.revoke('My Message as String')
# {'basescore': 0.0,
#  'code': 0,
#  'didremove': False,
#  'didset': True,
#  'headers': [],
#  'isspam': False,
#  'message': 'EX_OK',
#  'report': [],
#  'score': 0.0,
#  'symbols': []}
