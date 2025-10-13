#!/bin/bash -e
# Copyright (C) 2024 Simo Sorce <simo@redhat.com>
# SPDX-License-Identifier: Apache-2.0

title SECTION "Searching for Kryoptic module"

find_kryoptic() {
    for _lib in "$@" ; do
        if test -f "$_lib" ; then
            echo "Using kryoptic path $_lib"
            P11LIB="$_lib"
            return
        fi
    done
    echo "skipped: Unable to find kryoptic PKCS#11 library"
    exit 0
}

find_kryoptic \
    "${KRYOPTIC}/target/debug/libkryoptic_pkcs11.so" \
    "${KRYOPTIC}/target/release/libkryoptic_pkcs11.so" \
    /usr/local/lib/kryoptic/libkryoptic_pkcs11so \
    /usr/lib64/pkcs11/libkryoptic_pkcs11.so \
    /usr/lib/pkcs11/libkryoptic_pkcs11.so \
    /usr/lib/x86_64-linux-gnu/kryoptic/libkryoptic_pkcs11.so

title LINE "Creating Kyroptic database"

# Kryoptic configuration
cat << EOF > "$TOKDIR/kryoptic.conf"
[[slots]]
slot = 0
dbtype = "sqlite"
dbargs = "$TOKDIR/kryoptic.sql"
#mechanisms
EOF
export KRYOPTIC_CONF="${KRYOPTIC_CONF:-$TOKDIR/kryoptic.conf}"

export TOKENLABEL="${TOKENLABEL:-Kryoptic Token}"
export TOKENLABELURI="${TOKENLABELURI:-Kryoptic%20Token}"

# init token
pkcs11-tool --module "${P11LIB}" --init-token \
    --label "${TOKENLABEL}" --so-pin "${PINVALUE}" 2>&1
# set user pin
pkcs11-tool --module "${P11LIB}" --so-pin "${PINVALUE}" \
    --login --login-type so --init-pin --pin "${PINVALUE}" 2>&1

export TOKENCONFIGVARS="export KRYOPTIC_CONF=$TOKDIR/kryoptic.conf"

export TESTPORT="34000"

export SUPPORT_ALLOWED_MECHANISMS=1

# Enable SUPPORT_ML_DSA as long as it is not set already.
if [ -z "$SUPPORT_ML_DSA" ]; then
    export SUPPORT_ML_DSA=1
fi
# Enable SUPPORT_ML_KEM as long as it is not set already.
if [ -z "$SUPPORT_ML_KEM" ]; then
    export SUPPORT_ML_KEM=1
fi
