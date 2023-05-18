## Build Prerequisites

This package requires the following:
- OpenSSL 3.0.7+ libraries and development headers
- OpenSSL tools (for testing)
- autoconf-archive packages for some m4 macros
- NSS softoken, tools and development headers (for testing)
- a C compiler that supports at least C11 semantics
- automake
- pkg-config
- libtool
- p11-kit, p11-kit-server, p11-kit-devel, opensc and softhsm (for testing)

The usual command to build are:
- autoreconf -fi (if needed)
- ./configure (--with-openssl if needed)
- make
- make check

