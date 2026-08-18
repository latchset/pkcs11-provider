#!/bin/bash -e
# Copyright (C) 2022 Simo Sorce <simo@redhat.com>
# SPDX-License-Identifier: Apache-2.0

title SECTION "Setup NSS Softokn"

if ! command -v certutil &> /dev/null
then
    echo "NSS's certutil command is required"
    exit 0
fi

title LINE "Creating new NSS Database"
certutil -N -d "${TOKDIR}" -f "${PINFILE}"

export P11LIB="${SOFTOKNPATH%%/}/libsoftokn3${SHARED_EXT}"
export NSS_LIB_PARAMS="configDir=${TOKDIR}"

if [[ "${PKCS11_PROVIDER_FORCE_FIPS_MODE}" = "1" || "$(cat /proc/sys/crypto/fips_enabled)" = "1" ]]; then
    export TOKENLABEL="NSS FIPS 140-2 Certificate DB"
    export TOKENLABELURI="NSS%20FIPS%20140-2%20Certificate%20DB"
else
    export TOKENLABEL="NSS Certificate DB"
    export TOKENLABELURI="NSS%20Certificate%20DB"
fi

export TOKENOPTIONS="${TOKENOPTIONS}\npkcs11-module-quirks = no-allowed-mechanisms"
export TOKENCONFIGVARS="export NSS_LIB_PARAMS=configDir=${TOKDIR}"

export TESTPORT="30000"

# Edward curves are not well supported in NSS, Ed25519 requires a special OID
# for generation in ECParams, while Ed448 is not supported at all
export SUPPRESS_ED25519=1
export SUPPRESS_ED448=1

# Montgomery curves are not supported in NSS yet, but there is no way to
# autodetect it
export SUPPRESS_X25519=1
export SUPPRESS_X448=1

export SUPPORT_BLOCK_MODES="CBC CTR ECB"
export SUPPORT_OPERATION_STATE=1
