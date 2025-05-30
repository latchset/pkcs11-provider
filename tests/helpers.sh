#!/bin/bash -e
# Copyright (C) 2022 Simo Sorce <simo@redhat.com>
# SPDX-License-Identifier: Apache-2.0

: "${TESTBLDDIR=.}"

OPENSSL=$(which openssl3 2>/dev/null || true)
OPENSSL=${OPENSSL:-openssl}

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
        if [ -f "${PPDBGFILE}" ]; then
            echo "[TEST]: $*" >> "${PPDBGFILE}"
        fi
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

cleanup_server()
{
    echo "killing $1 server"
    kill -9 -- "$2"
}

helper_emit=1

ossl()
{
    helper_output=""
    if [[ "${2}" = "$helper_emit" ]]; then
        echo "# r $1" >> "${TMPPDIR}/gdb-commands.txt"
        echo "$CHECKER $OPENSSL $1"
        # shellcheck disable=SC2086  # this is intentionally split by words
        __out=$(eval $CHECKER $OPENSSL $1)
    else
        echo "# r $1 $2" >> "${TMPPDIR}/gdb-commands.txt"
        echo "$CHECKER $OPENSSL $1 $2"
        # shellcheck disable=SC2086  # this is intentionally split by words
        __out=$(eval $CHECKER $OPENSSL $1 $2)
    fi
    __res=$?
    if [[ "${2}" = "$helper_emit" ]]; then
        # shellcheck disable=SC2034  # used externally by caller
        helper_output="$__out"
    else
        echo "$__out"
    fi
    return $__res
}

gen_unsetvars() {
    grep "^export" "${TMPPDIR}/testvars" \
    | sed -e 's/export/unset/' -e 's/=.*$//' \
    >> "${TMPPDIR}/unsetvars"
}

kill_children() {
    # make sure it is killed before we continue
    jobs -p | xargs -r kill -9 || true
}

# macOS uses BSD sed, which expects the argument after -i (with a space after
# it!) to be the backup suffix, while GNU sed expects a potential backup suffix
# directly after -i and interprets -i <expression> as in-place editing with no
# backup.
#
# Use "${sed_inplace[@]}" to make that work transparently by setting it to the
# arguments required to achieve in-place editing without backups depending on
# the version of sed.
if sed --version 2>/dev/null | grep -q 'GNU sed'; then
	export sed_inplace=("-i")
else
	export sed_inplace=("-i" "")
fi

ptool() {
    # NSS uses the second slot for certificates, so we need to provide the token
    # label in the args to allow pkcs11-tool to find the right slot
    CMDOPTS=(--module="${P11LIB}" --token-label="${TOKENLABEL}")
    if [ -n "$P11DEFLOGIN" ]; then
        CMDOPTS+=("${P11DEFLOGIN[@]}")
    fi
    CMDOPTS+=("$@")
    $CHECKER pkcs11-tool "${CMDOPTS[@]}"
}
