#!/bin/bash -e
# Copyright (C) 2022 Jakub Jelen <jjelen@redhat.com>
# SPDX-License-Identifier: Apache-2.0

TMPPDIR="tmp.softhsm"
SOURCE_PATH=${SOURCE_PATH:-..}
source $SOURCE_PATH/tests/common.sh

if ! command -v softhsm2-util &> /dev/null
then
    echo "SoftHSM is is required"
    exit 77 # skip
fi

if [ "$P11KITCLIENTPATH" = "" ]; then
    echo "Missing P11KITCLIENTPATH env variable"
    exit 77 # skip
fi

OBJNAME="token_name"

find_softhsm() {
    for _lib in "$@" ; do
        if test -f "$_lib" ; then
            echo "Using softhsm path $_lib"
            P11LIB="$_lib"
            return
        fi
    done
    echo "skipped: Unable to find softhsm PKCS#11 library"
    exit 77 # skip
}

title SECTION "Searching for SoftHSM PKCS#11 library"
find_softhsm \
    /usr/local/lib/softhsm/libsofthsm2.so \
    /usr/lib64/pkcs11/libsofthsm2.so \
    /usr/lib/pkcs11/libsofthsm2.so \
    /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so

title SECTION "Set up testing system"

if [ -d ${TMPPDIR} ]; then
    rm -fr ${TMPPDIR}
fi
mkdir ${TMPPDIR}

# Create brand new tokens and certs
if [ -d ${TOKDIR} ]; then
    rm -fr ${TOKDIR}
fi
mkdir ${TOKDIR}

# Create SoftHSM configuration file
cat >"$TMPPDIR/softhsm.conf" <<EOF
directories.tokendir = $PWD/$TOKDIR
objectstore.backend = file
log.level = DEBUG
EOF

export SOFTHSM2_CONF=$TMPPDIR/softhsm.conf

dd if=/dev/urandom of=${SEEDFILE} bs=2048 count=1 >/dev/null 2>&1
echo ${PINVALUE} > ${PINFILE}

# init
softhsm2-util --init-token --label $OBJNAME --free --pin $PINVALUE --so-pin 12345678

title LINE "Export variables to ${TMPPDIR}/debugvars for easy debugging"
BASEDIR=$(pwd)
cat > ${TMPPDIR}/debugvars <<DBGSCRIPT
# debug vars, just 'source ${TMPPDIR}/debugvars'
export TOKDIR="${BASEDIR}/${TOKDIR}"
export TMPPDIR="${BASEDIR}/${TMPPDIR}"
DBGSCRIPT

if [ "$TEST_SETUP_SKIP_KEYS" != "1" ]; then
    # generate RSA key pair
    KEYID='0001'
    URIKEYID="%00%01"
    pkcs11-tool --keypairgen --key-type="RSA:2048" --login --pin=$PINVALUE --module="$P11LIB" --label="RSA" --id="$KEYID"

    BASEURIWITHPIN="pkcs11:id=${URIKEYID};pin-value=${PINVALUE}"
    BASEURI="pkcs11:id=${URIKEYID}"
    PUBURI="pkcs11:type=public;id=${URIKEYID}"
    PRIURI="pkcs11:type=private;id=${URIKEYID}"

    title LINE "RSA PKCS11 URIS"
    echo "${BASEURIWITHPIN}"
    echo "${BASEURI}"
    echo "${PUBURI}"
    echo "${PRIURI}"
    echo ""

    # generate ECC key pair
    KEYID='0002'
    URIKEYID="%00%02"
    pkcs11-tool --keypairgen --key-type="EC:secp256r1" --login --pin=$PINVALUE --module="$P11LIB" --label="ECC" --id="$KEYID"

    ECBASEURIWITHPIN="pkcs11:id=${URIKEYID};pin-value=${PINVALUE}"
    ECBASEURI="pkcs11:id=${URIKEYID}"
    ECPUBURI="pkcs11:type=public;id=${URIKEYID}"
    ECPRIURI="pkcs11:type=private;id=${URIKEYID}"

    KEYID='0003'
    URIKEYID="%00%03"
    pkcs11-tool --keypairgen --key-type="EC:secp256r1" --login --pin=$PINVALUE --module="$P11LIB" --label="PeerECC" --id="$KEYID"

    ECPEERBASEURIWITHPIN="pkcs11:id=${URIKEYID};pin-value=${PINVALUE}"
    ECPEERBASEURI="pkcs11:id=${URIKEYID}"
    ECPEERPUBURI="pkcs11:type=public;id=${URIKEYID}"
    ECPEERPRIURI="pkcs11:type=private;id=${URIKEYID}"

    title LINE "EC PKCS11 URIS"
    echo "${ECBASEURIWITHPIN}"
    echo "${ECBASEURI}"
    echo "${ECPUBURI}"
    echo "${ECPRIURI}"
    echo "${ECPEERBASEURIWITHPIN}"
    echo "${ECPEERBASEURI}"
    echo "${ECPEERPUBURI}"
    echo "${ECPEERPRIURI}"
    echo ""

    title PARA "Show contents of softhsm token"
    echo " ----------------------------------------------------------------------------------------------------"
    pkcs11-tool -O --login --pin=$PINVALUE --module="$P11LIB"
    echo " ----------------------------------------------------------------------------------------------------"

    title LINE "Export objects variables to ${TMPPDIR}/debugvars for easy debugging"
    BASEDIR=$(pwd)
    cat >> ${TMPPDIR}/debugvars <<DBGSCRIPT

export PINVALUE="${PINVALUE}"
export PINFILE="${BASEDIR}/${PINFILE}"
export TSTCRT="${BASEDIR}/${TSTCRT}"
export SEEDFILE="${BASEDIR}/${SEEDFILE}"

export BASEURIWITHPIN="${BASEURIWITHPIN}"
export BASEURI="${BASEURI}"
export PUBURI="${PUBURI}"
export PRIURI="${PRIURI}"
export ECBASEURI="${ECBASEURI}"
export ECPUBURI="${ECPUBURI}"
export ECPRIURI="${ECPRIURI}"
export ECPEERBASEURI="${ECPEERBASEURI}"
export ECPEERPUBURI="${ECPEERPUBURI}"
export ECPEERPRIURI="${ECPEERPRIURI}"
DBGSCRIPT


    TEST_RSAPSS="0"
    TEST_ECC_SHA2="0"
    TEST_OAEP_SHA2="0"
    TEST_HKDF="0"
fi

if [ "$TEST_SETUP_USE_PROXY" = "1" ]; then
    title PARA "Start the p11-kit server and check if it works"
    echo " ----------------------------------------------------------------------------------------------------"
    # p11-kit complains if there is not runtime directory
    if [ -z "$XDG_RUNTIME_DIR" ]; then
        export XDG_RUNTIME_DIR=$PWD
    fi
    eval $(p11-kit server --provider "$P11LIB" "pkcs11:")
    echo " ----------------------------------------------------------------------------------------------------"
    pkcs11-tool -O --login --pin=$PINVALUE --module="$P11KITCLIENTPATH"
    echo " ----------------------------------------------------------------------------------------------------"

    cleanup_p11_kit()
    {
        echo "killing p11-kit server"
        kill -9 -- $P11_KIT_SERVER_PID
    }

    title LINE "register clean function to kill p11-kit-server"
    trap "cleanup_p11_kit" EXIT

    title LINE "Set up environment variables"
    export PKCS11_PROVIDER_MODULE="${P11KITCLIENTPATH}"
else
    title LINE "Set up environment variables"
    export PKCS11_PROVIDER_MODULE="${P11LIB}"

    # SoftHSM does not like bogus arguments to C_Initialize()
    sed "/pkcs11-module-init-args/d" ${OPENSSL_CONF} > ${OPENSSL_CONF}.softhsm
    OPENSSL_CONF=${OPENSSL_CONF}.softhsm
fi

title LINE "Export more variables to ${TMPPDIR}/debugvars for easy debugging"
cat >> ${TMPPDIR}/debugvars <<DBGSCRIPT
export PKCS11_PROVIDER_MODULE=${PKCS11_PROVIDER_MODULE}
export OPENSSL_CONF="${OPENSSL_CONF}"
DBGSCRIPT

export PKCS11_PROVIDER_DEBUG="file:tmp.softhsm/p11prov-debug.log"
# for listing the separate pkcs11 calls
#export PKCS11SPY="${PKCS11_PROVIDER_MODULE}"
#export PKCS11_PROVIDER_MODULE=/usr/lib64/pkcs11-spy.so

title ENDSECTION
