#!/bin/bash -e
# Copyright (C) 2022 Simo Sorce <simo@redhat.com>
# SPDX-License-Identifier: Apache-2.0

# requires defined $TMPPDIR
TOKDIR="$TMPPDIR/tokens"
PINVALUE="12345678"
PINFILE="${PWD}/pinfile.txt"

TSTCRT="${TMPPDIR}/testcert.crt"
ECCRT="${TMPPDIR}/eccert.crt"
ECPEERCRT="${TMPPDIR}/ecpeercert.crt"
SEEDFILE="${TMPPDIR}/noisefile.bin"
SERIAL=0

# by default enable all tests
TEST_RSAPSS="1"
TEST_ECC_SHA2="1"
TEST_OAEP_SHA2="1"
TEST_HKDF="1"

title()
{
    case "$1" in
    "SECTION")
        shift 1
        echo "########################################"
        echo "## $*"
        echo ""
        ;;
    "ENDSECTION")
        echo ""
        echo "                                      ##"
        echo "########################################"
        echo ""
        ;;
    "PARA")
        shift 1
        echo ""
        echo "## $*"
        ;;
    "LINE")
        shift 1
        echo "$*"
        ;;
    *)
        echo "$*"
        ;;
    esac
}
