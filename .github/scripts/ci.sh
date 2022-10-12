#!/bin/bash -ex

if [ -f /etc/debian_version ]; then
    export DEBIAN_FRONTEND=noninteractive

    apt-get -q update

    apt-get -yq install $COMPILER make automake libtool pkg-config autoconf-archive \
        libssl-dev libnss3 libnss3-tools libnss3-dev

    apt-get -yq install python3-requests-gssapi 2>/dev/null || true
elif [ -f /etc/fedora-release ]; then
    dnf -y install $COMPILER automake libtool pkgconf-pkg-config autoconf-archive \
        openssl-devel nss-softokn nss-tools nss-softokn-devel openssl
else
    echo "Distro not found!"
    false
fi

autoreconf -fiv
CC=$COMPILER ./configure
make
make check
