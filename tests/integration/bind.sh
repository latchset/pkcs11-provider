#!/bin/bash -e
# Copyright (C) 2024 Ondrej Moris <omoris@redhat.com>
# SPDX-License-Identifier: Apache-2.0

# shellcheck disable=SC1091
source "../helpers.sh"

BASEDIR=$PWD
WORKDIR=$(mktemp -d)
PIN="123456"
PKCS11_DEBUG_FILE="${WORKDIR}/pkcs11-bind-test.log"

install_dependencies()
{
    title PARA "Install dependencies" 

    FEDORA_VERSION=$(rpm -q --qf "%{V}" fedora-release-common)
    if [ "$FEDORA_VERSION" -lt 39 ]; then
        echo "ERROR: This test requires at least Fedora 39!"
        exit 1
    elif [ "$FEDORA_VERSION" -eq 39 ]; then
        releasever="--releasever=40"
    fi
    dnf install -y "$releasever" --skip-broken \
        meson \
        p11-kit httpd mod_ssl openssl-devel gnutls-utils nss-tools \
        p11-kit-devel p11-kit-server opensc softhsm-devel procps-ng \
        openssl util-linux bind9-next opensc
}

softhsm_token_setup()
{    
    title PARA "Softhsm token setup"
    
    cp -rnp /var/lib/softhsm/tokens{,.bck}
    export PKCS11_PROVIDER_MODULE="/usr/lib64/pkcs11/libsofthsm2.so"
    softhsm2-util --init-token --free --label softhsm --pin $PIN --so-pin $PIN
    pkcs11-tool --module $PKCS11_PROVIDER_MODULE \
                --login --pin $PIN \
                --keypairgen --key-type rsa:2048 --label localhost-ksk
    pkcs11-tool --module $PKCS11_PROVIDER_MODULE \
                --login --pin $PIN \
                --keypairgen --key-type rsa:2048 --label localhost-zsk

    title SECTION "List token content"
    TOKENURL=$(p11tool --list-token-urls | grep "softhsm")
    p11tool --login --set-pin "$PIN" --list-all "$TOKENURL"
    title ENDSECTION
}

pkcs11_provider_setup()
{
    title PARA "Get, compile and install pkcs11-provider"

    if [ "$GITHUB_ACTIONS" == "true" ]; then
        if [ -z "$PKCS11_MODULE" ]; then
            echo "ERROR: Missing PKCS11_MODULE variable!"
            exit 1
        fi
        echo "Skipped (running in Github Actions)"
    else
        git clone \
            "${GIT_URL:-"https://github.com/latchset/pkcs11-provider.git"}" \
            "${WORKDIR}"/pkcs11-provider
        pushd "${WORKDIR}"/pkcs11-provider
        git checkout "${GIT_REF:-"main"}"
        meson setup -Dlibdir=/usr/lib64 builddir
        meson compile -C builddir
        meson install -C builddir
        popd
        export PKCS11_MODULE=/usr/lib64/ossl-modules/pkcs11.so
    fi
    test -e "$PKCS11_MODULE"
}

p11kit_server_setup()
{
    title PARA "Proxy module driver through p11-kit server"

    export XDG_RUNTIME_DIR=$PWD
    eval "$(p11-kit server --provider "$PKCS11_PROVIDER_MODULE" "pkcs11:")"
    test -n "$P11_KIT_SERVER_PID"
    export PKCS11_PROVIDER_MODULE="/usr/lib64/pkcs11/p11-kit-client.so"
}

openssl_setup()
{
    title PARA "OpenSSL setup"

    sed \
      -e "s|\(default = default_sect\)|\1\npkcs11 = pkcs11_sect\n|" \
      -e "s|\(\[default_sect\]\)|\[pkcs11_sect\]\n\1|" \
      -e "s|\(\[default_sect\]\)|module = $PKCS11_MODULE\n\1|" \
      -e "s|\(\[default_sect\]\)|pkcs11-module-load-behavior = early\n\1|" \
      -e "s|\(\[default_sect\]\)|activate = 1\n\n\1|" \
      /etc/pki/tls/openssl.cnf >"${WORKDIR}"/openssl.cnf

    title SECTION "openssl.cnf"
    cat "${WORKDIR}"/openssl.cnf
    title ENDSECTION
}

bind_setup()
{
    title PARA "Bind setup"

    cp /var/named/named.localhost "${WORKDIR}"/localhost
}

bind_test()
{
    title PARA "Bind test"

    TOKENURL=$(p11tool --list-token-urls | grep "softhsm")
    KSKURL="$(p11tool --login --set-pin "$PIN" --list-keys "$TOKENURL" \
        | grep 'URL:.*object=localhost-ksk' \
        | awk '{ print $NF }' \
        | sed "s/type=.*\$/pin-value=$PIN/")"
    ZSKURL="$(p11tool --login --set-pin "$PIN" --list-keys "$TOKENURL" \
        | grep 'URL:.*object=localhost-zsk' \
        | awk '{ print $NF }' \
        | sed "s/type=.*\$/pin-value=$PIN/")"

    pushd "$WORKDIR"

    title PARA "Test 1: Extract KSK and ZSK keys from PKCS11 URIs"
    PKCS11_PROVIDER_DEBUG=file:${PKCS11_DEBUG_FILE}.extract \
    OPENSSL_CONF=openssl.cnf \
        dnssec-keyfromlabel -a RSASHA256 -l "$ZSKURL" localhost
    PKCS11_PROVIDER_DEBUG=file:${PKCS11_DEBUG_FILE}.extract \
    OPENSSL_CONF=openssl.cnf \
        dnssec-keyfromlabel -a RSASHA256 -l "$KSKURL" -f KSK localhost
    for K in *.key; do
        cat "$K" >>localhost
    done
    test -s "${PKCS11_DEBUG_FILE}".extract
    
    title PARA "Test 2: Sign zone"
    PKCS11_PROVIDER_DEBUG=file:${PKCS11_DEBUG_FILE}.sign \
    OPENSSL_CONF=openssl.cnf \
        dnssec-signzone -o localhost localhost
    test -s "${PKCS11_DEBUG_FILE}".sign

    popd
    echo "Test passed"
}

cleanup() 
{
    title PARA "Clean-up"

    for L in "${PKCS11_DEBUG_FILE}".*; do
        title SECTION "$L"
        cat "$L"
        title ENDSECTION
    done

    pushd "$BASEDIR" >/dev/null
    rm -rf "$WORKDIR"
    if [ -e /var/lib/softhsm/tokens.bck ]; then
        rm -rf /var/lib/softhsm/tokens
        mv /var/lib/softhsm/tokens.bck /var/lib/softhsm/tokens
    fi
    cleanup_server "p11-kit" "$P11_KIT_SERVER_PID"

    title LINE "Done"
}


trap "cleanup" EXIT

# Setup.
install_dependencies
softhsm_token_setup
p11kit_server_setup
pkcs11_provider_setup
openssl_setup
bind_setup

# Test.
bind_test
