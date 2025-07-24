#!/bin/bash -ex
# Copyright (C) 2024 Jakub Zelenka <jakub.openssl@gmail.com>
# SPDX-License-Identifier: Apache-2.0
#

export SLOTID=42
export SLOT2ID=52
export TOKEN2LABEL="${TOKENLABEL:-Kryoptic Token 2}"
export TOKEN2LABELURI="${TOKENLABELURI:-Kryoptic%20Token%202}"
export PIN2VALUE=11111111

export KRYOPTIC_CONF="${TMPPDIR}/kryoptic.conf"
cat >"${KRYOPTIC_CONF}" <<_EOF
[[slots]]
slot = $SLOTID
dbtype = "sqlite"
dbargs = "$TOKDIR/kryoptic.sql"
#mechanisms
[[slots]]
slot = $SLOT2ID
dbtype = "sqlite"
dbargs = "${TOKDIR}/kryoptic2.sql"
description = "Kryoptic Token 2"
_EOF

# this overrides what we define in the generic init
export TOKENLABEL="Kryoptic Soft Token"
export TOKENLABELURI="Kryoptic%20Soft%20Token"

# the rest is the same
source "${TESTSSRCDIR}/kryoptic-init.sh"

# init token 2
pkcs11-tool --module "${P11LIB}" --init-token --slot "${SLOT2ID}" \
    --label "${TOKEN2LABEL}" --so-pin "${PIN2VALUE}" 2>&1
# set user pin 2
pkcs11-tool --module "${P11LIB}" --so-pin "${PIN2VALUE}" --slot "${SLOT2ID}" \
    --login --login-type so --init-pin --pin "${PIN2VALUE}" 2>&1

export TOKENCONFIGVARS="export KRYOPTIC_CONF=${TMPPDIR}/kryoptic.conf"
export TESTPORT="29000"

# generate RSA key
KEYID='0201'
URIKEYID="%02%01"

pkcs11-tool --module "${P11LIB}" --slot "${SLOT2ID}" --pin "${PIN2VALUE}" \
    --keypairgen --key-type="RSA:2048" --id="$KEYID" \
    --label="testKey" 2>&1

export BASEURI2WITHPINVALUE="pkcs11:id=${URIKEYID}?pin-value=${PINVALUE}"
export BASEURI2="pkcs11:id=${URIKEYID}"
export PUBURI2="pkcs11:type=public;id=${URIKEYID}"
export PRIURI2="pkcs11:type=private;id=${URIKEYID}"

title LINE "RSA PKCS11 URIS"
echo "${BASEURI2WITHPINVALUE}"
echo "${BASEURI2}"
echo "${PUBURI2}"
echo "${PRIURI2}"
echo ""

# While this works with the default DB, the NSS DB does not support this
# attribute
export SUPPORT_ALLOWED_MECHANISMS=0
