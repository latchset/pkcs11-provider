<!---
Copyright (C) 2022 Simo Sorce <simo@redhat.com>

SPDX-License-Identifier: Apache-2.0
-->

Quick'n'dirty HOWTO to get started until tests are in place

In openssl.cnf.in there is a scheleton example openssl configuration file that
uses NSS's softoken (chosen because it does not link openssl in it).

copy it as openssl.cnf, set the correct cknfig dirs in.

Initialize a token with and RSA keypair in tests/tokens
(or whatever you set in openssl.conf)
$ certutil -d tests/tokens -G

Export the conf file
$ export OPENSSL_CONF=/path/to/openssl.cnf

Try to export a public key:
openssl pkey -in "pkcs11:type=public" -pubin -pubout -out testkey.pub
