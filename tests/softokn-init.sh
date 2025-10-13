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

export TOKENOPTIONS="${TOKENOPTIONS}\npkcs11-module-quirks = no-operation-state no-allowed-mechanisms"
export TOKENCONFIGVARS="export NSS_LIB_PARAMS=configDir=${TOKDIR}"

export TESTPORT="30000"

# Edward curves are not supported in NSS yet
export SUPPORT_ED25519=0
export SUPPORT_ED448=0

export SUPPORT_ML_DSA=0
export SUPPORT_ML_KEM=0
