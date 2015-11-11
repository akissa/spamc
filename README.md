# spamc


## Python spamassassin spamc client library

spamc is a python module that provides fully compliant client side functionality of the
[spamassassin](https://spamassassin.apache.org)
[spamd protocol](https://github.com/apache/spamassassin/blob/trunk/spamd/PROTOCOL)

It can be used with [gevent](http://www.gevent.org) and [eventlet](http://www.eventlet.net),
is thread safe and supports streaming.

[![Build Status](https://travis-ci.org/akissa/spamc.svg)](https://travis-ci.org/akissa/spamc)
[![Code Climate](https://codeclimate.com/github/akissa/spamc/badges/gpa.svg)](https://codeclimate.com/github/akissa/spamc)
[![codecov.io](https://codecov.io/github/akissa/spamc/coverage.svg?branch=master)](https://codecov.io/github/akissa/spamc?branch=master)
[![Documentation Status](https://readthedocs.org/projects/spamc/badge/?version=latest)](http://spamc.readthedocs.org/en/latest/?badge=latest)
[![License](https://img.shields.io/badge/license-AGPLv3%2B-blue.svg)](https://github.com/akissa/spamc/blob/master/LICENSE)


## Installation

Install from PyPi

    pip install spamc

Install from Githib

    git clone https://github.com/akissa/spamc.git
    cd spamc
    python setup.py install

## Usage

Examples are in the [examples](https://github.com/akissa/spamc/tree/master/examples/) directory

```bash
$ ./examples/example1.py -h
Usage: example1.py [options]

Options:
  -h, --help            show this help message and exit
  -s SERVER, --server=SERVER
                        The spamassassin spamd server to connect to
  -p PORT, --port=PORT  The spamassassin spamd server port to connect to
  -u SOCKET_PATH, --unix-socket=SOCKET_PATH
                        The spamassassin spamd unix socket to connect to
  -t, --tls             Use TLS
  -z, --use-zlib-compression
                        Use Zlib compression
  -l COMPRESS_LEVEL, --zlib-compression-level=COMPRESS_LEVEL
                        Zlib compression level
  -a USER, --user=USER  Username of the user on whose behalfthis scan is being
                        performed
```

Module documentation is available on [readthedocs.org](https://spamc.readthedocs.org)

## Contributing

1. Fork it (https://github.com/akissa/spamc/fork)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request


## License

All code is licensed under the
[AGPLv3+ License](https://github.com/akissa/spamc/blob/master/LICENSE).
