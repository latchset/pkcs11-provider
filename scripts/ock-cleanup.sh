#!/bin/bash

########### generic ###########
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

########### ock-specific ###########

SLOT=${OCK_SLOT:-"3"}
PIN=${OCK_PIN:-"12345678"}

TMPDIR="tmp-ock"
unset OPENSSL_CONF

title SECTION "Cleanup (opencryptoki)"

title PARA "Remove directories"
rm -rf ${TMPDIR}

title PARA "Clean keys"

P11SAK=$(command -v p11sak)
if [ -z "${P11SAK}" ]; then
	title LINE "p11sak tool is required"
	title ENDSECTION
	exit 77
fi
P11SAK_ARGS="--slot ${SLOT} --pin ${PIN}"

title LINE "remove rsa keys"
LBL="ock_rsa2k"
${P11SAK} remove-key rsa --label "${LBL}:prv" --force ${P11SAK_ARGS} > /dev/null || true
${P11SAK} remove-key rsa --label "${LBL}:pub" --force ${P11SAK_ARGS} > /dev/null || true

title LINE "remove ec keys"
LBL="ock_ec256"
${P11SAK} remove-key ec --label "${LBL}:prv" --force ${P11SAK_ARGS} > /dev/null || true
${P11SAK} remove-key ec --label "${LBL}:pub" --force ${P11SAK_ARGS} > /dev/null || true

title PARA "Show contents of token in slot ${SLOT}"
${P11SAK} list-key all ${P11SAK_ARGS} | tail -n +2

title ENDSECTION
exit 0
