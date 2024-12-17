#!/bin/bash -ex
# Copyright (C) 2024 Jakub Jelen <jjelen@redhat.com>
# SPDX-License-Identifier: Apache-2.0
#

export KRYOPTIC_CONF="${TMPPDIR}/kryoptic.conf"
cat >"${KRYOPTIC_CONF}" <<_EOF
[[slots]]
slot = 42
dbtype = "nssdb"
dbargs = "configDir='${TOKDIR}' flags='passwordRequired'"
description = "Kryoptic Soft Token"
_EOF
# flags='passwordRequired' is needed for p11tool to do login before the
# search for private objects, otherwise the set up fails.

# this overrides what we define in the generic init
# the NSS DB can not store custom labels
export TOKENLABEL="Kryoptic Soft Token"
export TOKENLABELURI="Kryoptic%20Soft%20Token"

# the rest is the same
source "${TESTSSRCDIR}/kryoptic-init.sh"

export TOKENCONFIGVARS="export KRYOPTIC_CONF=${TMPPDIR}/kryoptic.conf"
export TOKENOPTIONS="pkcs11-module-quirks = no-allowed-mechanisms"
export TESTPORT="36000"
