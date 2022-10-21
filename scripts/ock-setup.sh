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

BASEDIR=$(pwd)
TMPDIR="tmp-ock"
PINFILE=${BASEDIR}/${TMPDIR}/pin.txt

title SECTION "Check & Configuration (opencryptoki)"
title PARA "check ock tools and libraries"

FAIL=0
LIBOCK=$(/sbin/ldconfig -p | awk '/libopencryptoki.so.0/ {print $4}' | head -n 1)
if [ -z "${LIBOCK}" ]; then
    title LINE "libopencryptoki not installed"
    FAIL=1
fi

if ! pidof pkcsslotd > /dev/null 2>&1 ; then
    title LINE "pkcsslotd not running"
    FAIL=1
fi

if ! groups | grep -qw pkcs11 ; then
    title LINE "missing group membership"
    FAIL=1
fi

PKCSCONF=$(command -v pkcsconf)
if [ -z "${PKCSCONF}" ]; then
    title LINE "pkcsconf tool is required"
    FAIL=1
fi

P11SAK=$(command -v p11sak)
if [ -z "${P11SAK}" ]; then
    title LINE "p11sak tool is required"
    FAIL=1
fi

if [ ${FAIL} -ne 0 ]; then
    title LINE "skip (tools/libary missing)"
    title ENDSECTION
    exit 77
fi

title LINE "library path: ${LIBOCK}"
title LINE "pkcsconf: ${PKCSCONF}"
title LINE "p11sak: ${P11SAK}"
title LINE "tools/library: ok"

title PARA "check ock configuration"

SLOT_CFG=$(pkcsconf -t -c ${SLOT})
if [ $? != 0 ]; then
    title LINE "[slot ${SLOT}]: token not working"
    FAIL=1
fi

${PKCSCONF} -t -c ${SLOT} | grep "Flags:" | grep -qw "TOKEN_INITIALIZED"
if [ $? != 0 ]; then
    title LINE "[token/slot ${SLOT}]: token not initialized"
    FAIL=1
fi

${PKCSCONF} -t -c ${SLOT} | grep "Flags:" | grep -qw "USER_PIN_INITIALIZED"
if [ $? != 0 ]; then
    title LINE "[token/slot ${SLOT}]: user-pin not initialized"
    FAIL=1
fi

${PKCSCONF} -t -c ${SLOT} | grep "Flags:" | grep -qw "USER_PIN_TO_BE_CHANGED"
if [ $? = 0 ]; then
    title LINE "[token/slot ${SLOT}]: user-pin need to be changed"
    FAIL=1
fi

if [ ${FAIL} -ne 0 ]; then
    title LINE "skip (configuration problems)"
    title ENDSECTION
    exit 77
fi

OCK_VERSION=$(${PKCSCONF} -i -c ${SLOT} | grep -Po 'Library Version: \K[^ ]*')
title LINE "library version: ${OCK_VERSION}"

OCK_TOKEN=$(${PKCSCONF} -t -c ${SLOT} | grep -Po 'Label: \K[^ ]*')
title LINE "token: ${OCK_TOKEN}"

title LINE "configuration: ok"
title ENDSECTION

title SECTION "Setup"

title PARA "Directories and files"
title LINE "reset temporary directory"
rm -rf ${TMPDIR}
mkdir -p ${TMPDIR}

echo ${PIN} > ${PINFILE}

R64K=${TMPDIR}/r64k.bin
dd if=/dev/urandom of=${R64K} bs=64K count=1 &> /dev/null

R256=${TMPDIR}/r256.bin
dd if=/dev/urandom of=${R256} bs=32 count=1 &>/dev/null

R512=${TMPDIR}/r512.bin
dd if=/dev/urandom of=${R512} bs=64 count=1 &>/dev/null

title PARA "Openssl configuration (prepare)"
if [ -z "${OPENSSL_CONF}" ]; then
    title LINE "skip (OPENSSL_CONF must be set)"
    title ENDSECTION
    exit 77
fi
if [ ! -f "${OPENSSL_CONF}" ]; then
    title LINE "skip (${OPENSSL_CONF} missing)"
    title ENDSECTION
    exit 77
fi
sed -e "s,^pkcs11-module-path = .*$,pkcs11-module-path = ${LIBOCK}," \
    -e "/^pkcs11-module-init-args = .*$/d" \
    -e "s,^pkcs11-module-token-pin = .*$,pkcs11-module-token-pin = file:${PINFILE}," \
    ${OPENSSL_CONF} \
> ${TMPDIR}/openssl.cnf
unset OPENSSL_CONF
title LINE "OPENSSL_CONF ${OPENSSL_CONF}"

title PARA "generate test keys (rsa)"

LBL="ock_rsa2k"
P11SAK_ARGS="--slot ${SLOT} --pin ${PIN}"

title LINE "clean-up"
${P11SAK} remove-key rsa --label "${LBL}:prv" --force ${P11SAK_ARGS} > /dev/null || true
${P11SAK} remove-key rsa --label "${LBL}:pub" --force ${P11SAK_ARGS} > /dev/null || true

title LINE "generate key-pair"
${P11SAK} generate-key rsa 2048 --attr "X:PSx" --label ${LBL} ${P11SAK_ARGS}

title PARA "RSA PKCS11 URIs"
BASEFILE="${TMPDIR}/${LBL}"
BASEURI=""
BASEURIWITHPIN=""
PUBURI="pkcs11:object=${LBL}:pub;type=public"
PRIURI="pkcs11:object=${LBL}:prv;type=private"
title LINE "BASEFILE       ${BASEFILE}"
title LINE "BASEURIWITHPIN ${BASEURIWITHPIN}"
title LINE "BASEURI        ${BASEURI}"
title LINE "PUBURI         ${PUBURI}"
title LINE "PRIURI         ${PRIURI}"

title PARA "generate test keys (ec)"
LBL="ock_ec256"

title LINE "clean-up"
${P11SAK} remove-key ec --label "${LBL}:prv" --force ${P11SAK_ARGS} > /dev/null || true
${P11SAK} remove-key ec --label "${LBL}:pub" --force ${P11SAK_ARGS} > /dev/null || true

title LINE "generate key-pair"
${P11SAK} generate-key ec prime256v1 --attr "X:PSx" --label ${LBL} ${P11SAK_ARGS}

ECBASEFILE="${TMPDIR}/${LBL}"
ECBASEURI=""
ECPUBURI="pkcs11:object=${LBL}:pub;type=public"
ECPRIURI="pkcs11:object=${LBL}:prv;type=private"

title PARA "EC PKCS11 URIs"
title LINE "ECBASEFILE      ${ECBASEFILE}"
title LINE "ECBASEURI       ${ECBASEURI}"
title LINE "ECPUBURI        ${ECPUBURI}"
title LINE "ECPRIURI        ${ECPRIURI}"

title PARA "Show contents of token in slot ${SLOT}"
p11sak list-key all ${P11SAK_ARGS} | tail -n +2
title LINE ""

title PARA "openssl configuration (activate)"
export OPENSSL_CONF="${TMPDIR}/openssl.cnf"
title LINE "OPENSSL_CONF ${OPENSSL_CONF}"

title PARA "Debug"
title LINE "Export variables to ${TMPDIR}/debugvars for easy debugging"
cat > ${TMPDIR}/debugvars << DBGSCRIPT
# debug vars, just 'source ${TMPDIR}/debugvars'
export TMPDIR="${BASEDIR}/${TMPDIR}"
export OPENSSL_CONF="${BASEDIR}/${OPENSSL_CONF}"

export PIN="${PIN}"
export PINFILE="${PINFILE}"
export R64K="${BASEDIR}/${R64K}"
export R256="${BASEDIR}/${R256}"
export R512="${BASEDIR}/${R512}"

export BASEFILE="${BASEDIR}/${BASEFILE}"
export BASEURIWITHPIN="${BASEURIWITHPIN}"
export BASEURI="${BASEURI}"
export PUBURI="${PUBURI}"
export PRIURI="${PRIURI}"
export ECBASEFILE="${BASEDIR}/${ECBASEFILE}"
export ECBASEURI="${ECBASEURI}"
export ECPUBURI="${ECPUBURI}"
export ECPRIURI="${ECPRIURI}"
DBGSCRIPT

cat > ${TMPDIR}/unsetvars << UNSETSCRIPT
# unset debug vars, just 'source ${TMPDIR}/debugvars'
unset TMPDIR
unset OPENSSL_CONF

unset PIN
unset PINFILE

unset BASEFILE
unset BASEURIWITHPIN
unset BASEURI
unset PUBURI
unset PRIURI
unset ECBASEFILE
unset ECBASEURI
unset ECPUBURI
unset ECPRIURI
UNSETSCRIPT

title ENDSECTION

exit 0
