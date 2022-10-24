OpenSSL
=======

The openssl test-suite performs operation with existing key-material in a
PKCS#11 setup. All information between the PKCS#11 setup and the test-suite
is contained in exported environment variables of the PKCS#11 setup.

Usage
=====

Before running the openssl test-suite, the PKCS#11 environment must be
set-up. This can be done manually or by executing the appropriate setup
script.

Example with opencryptoki:

.. code-block::

   # run the setup script for the PKCS#11 module
   OPENSSL_CONF=tests/openssl.cnf scripts/ock-setup.sh

   # export all variables of the setup script
   source tmp-ock/debugvars

   # run test-suite
   tests/test-openssl.sh

   # unset all variables (optional)
   source tmp-ock/unsetvars

Debugging
=========

All executed openssl commands are written as gdb commands to the
`gdb_commands.txt` file in the temporary directory. It can be used for
debugging sessions.

Test-Suite API
==============

The Openssl test-suite script is based on environment variables. They
contain setting and key references. The test-suite checks the environment
variable with a key reference, before it executes the test. Tests for
non-set or empty key references will be skipped.

The following settings are mandatory:

- TMPDIR: path to a temporary directory for the PKCS#11 module setup
- OPENSSL_CONF: path to the openssl provider configuration
- R64K: path to a file with 64k random data
- R256: path to a file with 256bit random data (32 byte)
- R512: path to a file with 512bit random data (64 byte)

The following RSA key references are used:

- BASEFILE: base path to a key file (without type suffix)
- BASEURI: PKCS#11 URI to a key (no type)
- PUBURI: PKCS#11 URI to a private key
- PRIURI: PKCS#11 URI to a public key

The following RSA key references are used:

- ECBASEFILE: base path to a key file (without type suffix)
- ECBASEURI: PKCS#11 URI to a key (no type)
- ECPUBURI: PKCS#11 URI to a private key
- ECPRIURI: PKCS#11 URI to a public key
