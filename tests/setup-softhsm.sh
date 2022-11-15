#!/bin/bash -e
# Copyright (C) 2022 Jakub Jelen <jjelen@redhat.com>
# SPDX-License-Identifier: Apache-2.0

source helpers.sh

if ! command -v softhsm2-util &> /dev/null
then
    echo "SoftHSM is is required"
    exit 77 # skip
fi

if [ "$P11KITCLIENTPATH" = "" ]; then
    echo "Missing P11KITCLIENTPATH env variable"
    exit 77 # skip
fi

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

TMPPDIR="tmp.softhsm"

if [ -d ${TMPPDIR} ]; then
    rm -fr ${TMPPDIR}
fi
mkdir ${TMPPDIR}

PINVALUE="12345678"
PINFILE="${PWD}/pinfile.txt"
echo ${PINVALUE} > ${PINFILE}

#RANDOM data
SEEDFILE="${TMPPDIR}/noisefile.bin"
dd if=/dev/urandom of=${SEEDFILE} bs=2048 count=1 >/dev/null 2>&1
RAND64FILE="${TMPPDIR}/64krandom.bin"
dd if=/dev/urandom of=${RAND64FILE} bs=2048 count=32 >/dev/null 2>&1

# Create brand new tokens and certs
TOKDIR="$TMPPDIR/tokens"
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

# init
softhsm2-util --init-token --label "token_name" --free --pin $PINVALUE --so-pin $PINVALUE

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

title PARA "Output configurations"
BASEDIR=$(pwd)
OPENSSL_CONF=${BASEDIR}/${TMPPDIR}/openssl.cnf

title LINE "Generate openssl config file"
sed -e "s|@libtoollibs[@]|${LIBSPATH}|g" \
    -e "s|@testsdir[@]|${BASEDIR}|g" \
    -e "/pkcs11-module-init-args/d" \
    openssl.cnf.in > ${OPENSSL_CONF}

title LINE "Export test variables to ${TMPPDIR}/testvars"
cat >> ${TMPPDIR}/testvars <<DBGSCRIPT
export P11LIB=${P11LIB}
export P11KITCLIENTPATH=${P11KITCLIENTPATH}
export PKCS11_PROVIDER_MODULE=${P11LIB}
export PKCS11_PROVIDER_DEBUG="file:${BASEDIR}/${TMPPDIR}/p11prov-debug.log"
export OPENSSL_CONF="${OPENSSL_CONF}"
export SOFTHSM2_CONF=${BASEDIR}/${TMPPDIR}/softhsm.conf

export TOKDIR="${BASEDIR}/${TOKDIR}"
export TMPPDIR="${BASEDIR}/${TMPPDIR}"
export PINVALUE="${PINVALUE}"
export PINFILE="${BASEDIR}/${PINFILE}"
export SEEDFILE="${BASEDIR}/${TMPPDIR}/noisefile.bin"
export RAND64FILE="${BASEDIR}/${TMPPDIR}/64krandom.bin"

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

# for listing the separate pkcs11 calls
#export PKCS11SPY="${PKCS11_PROVIDER_MODULE}"
#export PKCS11_PROVIDER_MODULE=/usr/lib64/pkcs11-spy.so
DBGSCRIPT

title ENDSECTION
