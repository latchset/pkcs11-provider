#!/bin/bash -e
# Copyright (C) 2024 Ondrej Moris <omoris@redhat.com>
# SPDX-License-Identifier: Apache-2.0

# shellcheck disable=SC1091
source "../helpers.sh"

BASEDIR=$PWD
WORKDIR=$(mktemp -d)
PKCS11_DEBUG_FILE="${WORKDIR}/pkcs11-libssh-test.log"

install_dependencies()
{
    title PARA "Install dependencies" 
    
    dnf install -y --skip-broken cmake libcmocka libcmocka-devel softhsm \
      nss-tools gnutls-utils p11-kit p11-kit-devel p11-kit-server opensc \
      softhsm-devel socket_wrapper nss_wrapper uid_wrapper pam_wrapper \
      priv_wrapper openssh-server zlib-devel git meson \
      openssl-devel gcc g++ libcmocka-devel 
}

pkcs11_provider_setup()
{
    title PARA "Get, compile and install pkcs11-provider"

    if [ "$GITHUB_ACTIONS" == "true" ]; then
        echo "Skipped (running in Github Actions)"
        if [ -z "$PKCS11_MODULE" ]; then
            echo "ERROR: Missing PKCS11_MODULE variable!"
            exit 1
        fi
    else
        git clone \
          "${GIT_URL:-"https://github.com/latchset/pkcs11-provider.git"}" \
          "${WORKDIR}"/pkcs11-provider
        pushd "$WORKDIR"/pkcs11-provider
        git checkout "${GIT_REF:-"main"}"
        meson setup -Dlibdir=/usr/lib64 builddir
        meson compile -C builddir
        meson install -C builddir
        popd
        export PKCS11_MODULE=/usr/lib64/ossl-modules/pkcs11.so
    fi
    test -e "$PKCS11_MODULE"
}

libssh_setup()
{
    title PRAM "Clone, setup and build libssh"

    git clone https://gitlab.com/libssh/libssh-mirror.git \
      "${WORKDIR}"/libssh-mirror

    mkdir "${WORKDIR}"/libssh-mirror/build
    pushd "${WORKDIR}"/libssh-mirror/build
    cmake \
      -DUNIT_TESTING=ON \
      -DCLIENT_TESTING=ON \
      -DCMAKE_BUILD_TYPE=Debug \
      -DWITH_PKCS11_URI=ON \
      -DWITH_PKCS11_PROVIDER=ON \
      -DPKCS11_PROVIDER="${PKCS11_MODULE}" ..
    make
    popd
}

libssh_test()
{
    title PARAM "Run libssh pkcs11 tests"

    pushd "${WORKDIR}"/libssh-mirror/build
    PKCS11_PROVIDER_DEBUG=file:$PKCS11_DEBUG_FILE ctest \
      --output-on-failure -R \
      '(torture_auth_pkcs11|torture_pki_rsa_uri|torture_pki_ecdsa_uri)' \
     | tee testout.log 2>&1
    grep -q "100% tests passed, 0 tests failed out of 3" testout.log
    test -s "$PKCS11_DEBUG_FILE"
   
    echo "Test passed"
    popd
}

# shellcheck disable=SC2317
cleanup() 
{
    title PARA "Clean-up"

    title SECTION "$PKCS11_DEBUG_FILE"
    cat "$PKCS11_DEBUG_FILE"
    title ENDSECTION

    pushd "$BASEDIR" >/dev/null
    rm -rf "$WORKDIR"

    title LINE "Done"
}

trap "cleanup" EXIT

# Setup.
install_dependencies
pkcs11_provider_setup
libssh_setup

# Test.
libssh_test
