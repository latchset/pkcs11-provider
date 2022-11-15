#!/bin/bash -e
# Copyright (C) 2022 Jakub Jelen <jjelen@redhat.com>
# SPDX-License-Identifier: Apache-2.0

source helpers.sh

# p11-kit complains if there is not runtime directory
if [ -z "$XDG_RUNTIME_DIR" ]; then
    export XDG_RUNTIME_DIR=$PWD
fi

title PARA "Start the p11-kit server and check if it works"
eval $(p11-kit server --provider "$P11LIB" "pkcs11:")

pkcs11-tool -O --login --pin=$PINVALUE --module="$P11KITCLIENTPATH" > /dev/null

#register clean function to kill p11-kit-server
trap "cleanup_server p11-kit $P11_KIT_SERVER_PID" EXIT

#Set up environment variables
export PKCS11_PROVIDER_MODULE="${P11KITCLIENTPATH}"

$*
