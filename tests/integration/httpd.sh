#!/bin/bash -e
# Copyright (C) 2024 Ondrej Moris <omoris@redhat.com>
# SPDX-License-Identifier: Apache-2.0

# shellcheck disable=SC1091
source "../helpers.sh"

BASEDIR=$PWD
WORKDIR=$(mktemp -d)
PIN="123456"
PIN_FILE="${WORKDIR}/pin.txt"
PKCS11_DEBUG_FILE="${WORKDIR}/pkcs11-httpd-test.log"
MOD_SSL_CONF="/etc/httpd/conf.d/ssl.conf"

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
        openssl util-linux
}

softhsm_token_setup()
{    
    title PARA "Softhsm token setup"
    
    pushd "$WORKDIR"
    mkdir ca server
    openssl req -x509 -sha256 -newkey rsa:2048 -noenc -batch \
        -keyout ca/key.pem -out ca/cert.pem
    openssl req -newkey rsa:2048 -subj '/CN=localhost' -noenc -batch \
        -keyout server/key.pem -out server/csr.pem
    openssl x509 -req -CA ca/cert.pem -CAkey ca/key.pem \
        -in server/csr.pem -out server/cert.pem -CAcreateserial
    chown -R apache:apache "$WORKDIR"

    usermod -a -G ods apache
    cp -rnp /var/lib/softhsm/tokens{,.bck}
    runuser -u apache -- \
        softhsm2-util --init-token --free --label softtoken --pin $PIN --so-pin $PIN
    TOKENURL=$(p11tool --list-token-urls | grep "softtoken")
    runuser -u apache -- p11tool \
        --write \
        --load-privkey server/key.pem \
        --label httpd \
        --id=%01 \
        --login \
        --set-pin "$PIN" "$TOKENURL"
    runuser -u apache -- p11tool \
        --write \
        --load-certificate server/cert.pem \
        --label httpd \
        --id=%01 \
        --login \
        --set-pin "$PIN" "$TOKENURL"
    popd

    export PKCS11_PROVIDER_MODULE="/usr/lib64/pkcs11/libsofthsm2.so"

    title SECTION "List token content"
    p11tool --login --set-pin "$PIN" --list-all "$TOKENURL" 
    title ENDSECTION
}

pkcs11_provider_setup()
{
    title PARA "Get, compile and install pkcs11-provider"

    export PKCS11_PROVIDER_DEBUG=file:$PKCS11_DEBUG_FILE
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

openssl_setup()
{
    title PARA "OpenSSL setup"

    echo "$PIN" >"$PIN_FILE"
    sed \
      -e "s|\(default = default_sect\)|\1\npkcs11 = pkcs11_sect\n|" \
      -e "s|\(\[default_sect\]\)|\[pkcs11_sect\]\n\1|" \
      -e "s|\(\[default_sect\]\)|module = $PKCS11_MODULE\n\1|" \
      -e "s|\(\[default_sect\]\)|pkcs11-module-load-behavior = early\n\1|" \
      -e "s|\(\[default_sect\]\)|pkcs11-module-token-pin = file:$PIN_FILE\n\1|" \
      -e "s|\(\[default_sect\]\)|activate = 1\n\n\1|" \
      /etc/pki/tls/openssl.cnf >"${WORKDIR}"/openssl.cnf

    title SECTION "openssl.cnf"
    cat "${WORKDIR}"/openssl.cnf
    title ENDSECTION
}

httpd_setup()
{
    title PARAM "Httpd setup"

    TOKENURL=$(p11tool --list-token-urls | grep "softtoken")
    KEYURL="$(p11tool --login --set-pin "$PIN" --list-keys "$TOKENURL" \
        | grep 'URL:.*object=httpd;type=private' \
        | awk '{ print $NF }')?pin-value=$PIN"
    CERTURL=$(p11tool --list-all-certs "$TOKENURL" \
        | grep "URL:.*object=httpd;type=cert" \
        | awk '{ print $NF }')

    cp -p $MOD_SSL_CONF{,.bck}
    sed -i -e "/^SSLCryptoDevice/d" \
           -e "s/^SSLCertificateFile.*\$/SSLCertificateFile \"$CERTURL\"/" \
           -e "s/^SSLCertificateKeyFile.*\$/SSLCertificateKeyFile \"$KEYURL\"/" \
           $MOD_SSL_CONF
    # echo 'ServerName localhost:80' >>/etc/httpd/conf/httpd.conf
           
    title SECTION "$MOD_SSL_CONF"
    cat $MOD_SSL_CONF
    title ENDSECTION
}

httpd_test()
{
    title PARA "Httpd test"

    title PARA "Test 1: Start httpd"
    PKCS11_PROVIDER_DEBUG=file:${PKCS11_DEBUG_FILE}.httpd_start \
    OPENSSL_CONF=${WORKDIR}/openssl.cnf httpd -DFOREGROUND &
    sleep 3
    if ! pgrep httpd >/dev/null; then
        echo "ERROR: Unable to start httpd!"
        exit 1 
    fi

    title PARA "Test 2: Curl connects to httpd over TLS"
    PKCS11_PROVIDER_DEBUG=file:${PKCS11_DEBUG_FILE}.curl \
    curl -v -sS --cacert "${WORKDIR}"/ca/cert.pem https://localhost >/dev/null

    echo "Test passed"
}

# shellcheck disable=SC2317
cleanup() 
{
    title PARA "Clean-up"

    for L in "${PKCS11_DEBUG_FILE}".*; do
        title SECTION "$L"
        cat "$L"
        title ENDSECTION
    done
    ssl_log="/var/log/httpd/ssl_error_log" 
    if [ -e "$ssl_log" ]; then
        title SECTION "$ssl_log"
        cat "$ssl_log"
        title ENDSECTION
    fi

    pushd "$BASEDIR" >/dev/null
    rm -rf "$WORKDIR"
    if pgrep httpd >/dev/null; then
        pkill httpd
    fi
    if [ -e "${MOD_SSL_CONF}".bck ]; then
        mv "${MOD_SSL_CONF}".bck "$MOD_SSL_CONF"
    fi
    if [ -e /var/lib/softhsm/tokens.bck ]; then
        rm -rf /var/lib/softhsm/tokens
        mv /var/lib/softhsm/tokens.bck /var/lib/softhsm/tokens
    fi

    title LINE "Done"
}

trap "cleanup" EXIT

# Setup.
install_dependencies
softhsm_token_setup
pkcs11_provider_setup
openssl_setup
httpd_setup

# Test.
httpd_test
