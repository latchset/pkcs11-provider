#!/bin/bash -e
# Copyright (C) 2022 Jakub Jelen <jjelen@redhat.com>
# SPDX-License-Identifier: Apache-2.0

title SECTION "Searching for SoftHSM PKCS#11 library"

if ! command -v softhsm2-util &> /dev/null
then
    echo "SoftHSM is is required"
    exit 0
fi

find_softhsm() {
    for _lib in "$@" ; do
        if test -f "$_lib" ; then
            echo "Using softhsm path $_lib"
            P11LIB="$_lib"
            return
        fi
    done
    echo "skipped: Unable to find softhsm PKCS#11 library"
    exit 0
}

# Attempt to guess the path to libsofthsm2.so relative to that. This fixes
# auto-detection on platforms such as macOS with MacPorts (and potentially
# Homebrew).
#
# This should never be empty, since we checked for the presence of
# softhsm2-util above and use it below.

# Strip bin/softhsm2-util
softhsm_prefix=$(dirname "$(dirname "$(type -p softhsm2-util)")")

find_softhsm \
    "$softhsm_prefix/lib64/softhsm/libsofthsm2.so" \
    "$softhsm_prefix/lib/softhsm/libsofthsm2.so" \
    "$softhsm_prefix/lib64/pkcs11/libsofthsm2.so" \
    "$softhsm_prefix/lib/pkcs11/libsofthsm2.so" \
    /usr/local/lib/softhsm/libsofthsm2.so \
    /usr/lib64/pkcs11/libsofthsm2.so \
    /usr/lib/pkcs11/libsofthsm2.so \
    /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so

export P11LIB

title SECTION "Set up testing system"

# Create SoftHSM configuration file
cat >"$TMPPDIR/softhsm.conf" <<EOF
directories.tokendir = $TOKDIR
objectstore.backend = file
log.level = DEBUG
EOF

export SOFTHSM2_CONF=$TMPPDIR/softhsm.conf

export TOKENLABEL="SoftHSM Token"
export TOKENLABELURI="SoftHSM%20Token"

# init
softhsm2-util --init-token --label "${TOKENLABEL}" --free --pin "${PINVALUE}" --so-pin "${PINVALUE}"

#softhsm crashes on de-init so we need to default to this quirk
export TOKENOPTIONS="pkcs11-module-quirks = no-deinit no-operation-state"

export TOKENCONFIGVARS="export SOFTHSM2_CONF=${TMPPDIR}/softhsm.conf"
