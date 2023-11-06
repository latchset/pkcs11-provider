#!/bin/bash -e
# Copyright (C) 2022 Simo Sorce <simo@redhat.com>
# SPDX-License-Identifier: Apache-2.0

: "${TESTBLDDIR=.}"

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

cleanup_server()
{
    echo "killing $1 server"
    kill -9 -- "$2"
}

helper_emit=1

ossl()
{
    helper_output=""
    echo "# r $1" >> "${TMPPDIR}/gdb-commands.txt"
    echo "$CHECKER openssl $1"
    # shellcheck disable=SC2086  # this is intentionally split by words
    __out=$(eval $CHECKER openssl $1)
    __res=$?
    if [ "${2:-0}" -eq "$helper_emit" ]; then
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
