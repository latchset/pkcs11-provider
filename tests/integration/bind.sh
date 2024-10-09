#!/bin/bash -e
# Copyright (C) 2024 Ondrej Moris <omoris@redhat.com>
# SPDX-License-Identifier: Apache-2.0

if [ $# -ne 1 ]; then
    echo "Usage bind.sh <tokentype>"
    exit 1
fi

# shellcheck disable=SC1091
source "../helpers.sh"

TOKENTYPE=$1

# Temporary dir and Token data dir
TMPPDIR="/tmp/bind/${TOKENTYPE}"
TOKDIR="$TMPPDIR/tokens"
if [ -d "${TMPPDIR}" ]; then
    rm -fr "${TMPPDIR}"
fi
mkdir -p "${TMPPDIR}"
mkdir "${TOKDIR}"

PINVALUE="123456"
PINFILE="${TMPPDIR}/pinfile.txt"
echo ${PINVALUE} > "${PINFILE}"
PKCS11_DEBUG_FILE="${TMPPDIR}/pkcs11-bind-test.log"
TEST_RESULT=1

token_setup()
{
    title PARA "Token setup"

    if [ "${TOKENTYPE}" == "softhsm" ]; then
        # shellcheck disable=SC1091
        source "../softhsm-init.sh"
        export XDG_RUNTIME_DIR=$PWD
        eval "$(p11-kit server --provider "$P11LIB" "pkcs11:")"
        test -n "$P11_KIT_SERVER_PID"
        export P11LIB="/usr/lib64/pkcs11/p11-kit-client.so"
    elif [ "${TOKENTYPE}" == "softokn" ]; then
        # shellcheck disable=SC1091
        SHARED_EXT=".so" SOFTOKNPATH="/usr/lib64" source "../softokn-init.sh"
    elif [ "${TOKENTYPE}" == "kryoptic" ]; then
        # shellcheck disable=SC1091
        source "../kryoptic-init.sh"
    else
        echo "Unknown token type: $TOKENTYPE"
        exit 1
    fi
    export PKCS11_PROVIDER_MODULE=$P11LIB
    ${TOKENCONFIGVARS}

    ARGS=("--module=${P11LIB}" "--login" "--pin=${PINVALUE}" "--token-label=${TOKENLABEL}")
    pkcs11-tool "${ARGS[@]}" --keypairgen --key-type rsa:2048 --id '0001' --label localhost-ksk
    pkcs11-tool "${ARGS[@]}" --keypairgen --key-type rsa:2048 --id '0002' --label localhost-zsk

    title SECTION "List token content"
    pkcs11-tool "${ARGS[@]}" -O
    title ENDSECTION
}

openssl_setup()
{
    title PARA "OpenSSL setup"

    sed \
      -e "s|\(default = default_sect\)|\1\npkcs11 = pkcs11_sect\n|" \
      -e "s|\(\[default_sect\]\)|\[pkcs11_sect\]\n$TOKENOPTIONS\n\1|" \
      -e "s|\(\[default_sect\]\)|module = $PKCS11_MODULE\n\1|" \
      -e "s|\(\[default_sect\]\)|activate = 1\n\n\1|" \
      -e "s|\(\[default_sect\]\)|pkcs11-module-token-pin = file:$PINFILE\n\1|" \
      /etc/pki/tls/openssl.cnf >"${TMPPDIR}"/openssl.cnf
}

bind_setup()
{
    title PARA "Bind setup"

    cp /var/named/named.localhost "${TMPPDIR}"/localhost
}

bind_test()
{
    title PARA "Bind test"
    (
        export OPENSSL_CONF=${TMPPDIR}/openssl.cnf
        export PKCS11_PROVIDER_DEBUG=file:${PKCS11_DEBUG_FILE}

        title SECTION "Test 1: Extract KSK and ZSK keys from PKCS11 URIs"
        dnssec-keyfromlabel -a RSASHA256 -l "pkcs11:object=localhost-zsk" -K "$TMPPDIR" localhost
        dnssec-keyfromlabel -a RSASHA256 -l "pkcs11:object=localhost-ksk" -K "$TMPPDIR" -f KSK localhost
        for K in "${TMPPDIR}"/*.key; do
            cat "$K" >>"${TMPPDIR}/localhost"
        done
        test -s "${PKCS11_DEBUG_FILE}"
        title ENDSECTION

        title SECTION "Test 2: Sign zone"
        dnssec-signzone -o localhost -K "$TMPPDIR" "${TMPPDIR}/localhost"
        test -s "${PKCS11_DEBUG_FILE}"
        title ENDSECTION
    )
    title LINE "PASSED"
    TEST_RESULT=0
}

# shellcheck disable=SC2317
cleanup() 
{
    title PARA "Clean-up"

    if [ "$TEST_RESULT" -ne 0 ]; then
        for L in ${TMPPDIR}/openssl.cnf $PKCS11_DEBUG_FILE; do
            if [ -e "$L" ]; then
                title SECTION "$L"
                cat "$L"
                title ENDSECTION
            fi
        done
    fi

    if [ "${TOKENTYPE}" == "softhsm" ]; then
        cleanup_server "p11-kit" "$P11_KIT_SERVER_PID"
    fi
}

trap "cleanup" EXIT

# Setup.
token_setup
openssl_setup
bind_setup

# Test.
bind_test

exit $TEST_RESULT
