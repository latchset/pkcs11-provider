## Build Prerequisites

This package requires the following:
- OpenSSL 3.0+ libraries and development headers
- autoconf-archives packages for some m4 macros
- NSS softoken and development headers (for testing)
- a C compiler that supports at least C11 semantics

The usual command to build are:
- autoreconf -fi (if needed)
- ./configure
- make
- make check
