Opencryptoki
============

The PKCS#11 implementation `opencryptoki` can be used with the
pkcs11-provider. This document describes a basic installation and setup for
testing purposes with the pkcs11-provider.

Installation as package
=======================

Install opencryptoki from the distribution's repository.

RedHat/Fedora
-------------

Install the base packages (including depending packages):

    sudo dnf install opencryptoki

For the pkcs11-provider testing environment, the software token is required.
Other token libraries can be installed as well.

    sudo dnf install opencryptoki-swtok

The location of the default configuration for opencryptoki is
`/etc/opencryptoki/opencryptoki.conf`

Debian/Ubuntu
-------------

Install the base packages (including depending packages):

    sudo apt install opencryptoki

The location of the default configuration for opencryptoki is
`/etc/opencryptoki/opencryptoki.conf`

Installation from source
========================

Get the source from github, build and install.
		
    git clone https://github.com/opencryptoki/opencryptoki.git
    cd opencryptoki
    ./bootstrap
    ./configure
    make
    sudo make install
    sudo ldconfig

The location of the default configuration for opencryptoki is
`/usr/local/etc/opencryptoki/opencryptoki.conf`

Configuration
=============

For the pkcs11-provider tests, the default configuration should be
sufficient. If the opencryptoki configuration has changed, please run the
initialization script once.

    sudo scripts/ock-once-swtok.sh

The initialization script will only work with the swtok. If another token
should be used, it must be initialized manually.

The initialization script uses a default user pin. If another pin should be
used, please specify it in the environment variable OCK_PIN.

    sudo OCK_PIN=11223344 scripts/ock-once-swtok.sh

Setup
=====

The pkcs11-provider tests require an openssl configuration and a set of keys
in the token for testing purposes. The setup script will prepare all these.

    export OPENSSL_CONF=tests/openssl.cnf
    scripts/ock-setup.sh

The setup script uses by default the swtok in slot 3. If another slot should
be used, specify it in the environment variable OCK_SLOT.

    OCK_SLOT=0 scripts/ock-setup.sh

.. warning::

     Attention: The setup script will remove all keys with label
     `test_rsa2k` and `test_ec256` in the token!

The setup script uses a default user pin. If another pin should be used,
please specify it in the environment variable OCK_PIN. If a user pin has
been used for the initialization script, the same should be used for the
setup script.

    OCK_PIN=11223344 scripts/ock-setup.sh

Files
-----

The setup script will create a set of files in the temporary directory
`tmp-ock`.

- openssl.cnf: contains the openssl configuration for pkcs11-provider and
  opencryptoki
- pin.txt: contains the user pin
- debugvars: exports environment variables for debugging
- unsetvars: unsets environment variables (after debugging)

Cleanup
=======

The test keys and the temporary directory can be removed with the cleanup
script.

    scripts/ock_cleanup.sh

.. warning::

     Attention: The cleanup script will remove all keys with label
     `test_rsa2k` and `test_ec256` in the token!

The cleanup script supports the same environment variables as the setup
script.
