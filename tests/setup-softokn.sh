#!/bin/bash -e
# Copyright (C) 2022 Simo Sorce <simo@redhat.com>
# SPDX-License-Identifier: Apache-2.0

TMPPDIR="tmp.softokn"
SOURCE_PATH=${SOURCE_PATH:-..}
source $SOURCE_PATH/tests/common.sh

if ! command -v certutil &> /dev/null
then
    echo "NSS's certutil command is required"
    exit 77
fi

title SECTION "Set up testing system"

# Create brand new tokens and certs
if [ -d ${TMPPDIR} ]; then
    rm -fr ${TMPPDIR}
fi
mkdir ${TMPPDIR}

if [ -d ${TOKDIR} ]; then
    rm -fr ${TOKDIR}
fi
mkdir ${TOKDIR}

dd if=/dev/urandom of=${SEEDFILE} bs=2048 count=1 >/dev/null 2>&1
echo ${PINVALUE} > ${PINFILE}

title LINE "Creating new NSS Database"
certutil -N -d ${TOKDIR} -f ${PINFILE}

title LINE "Export variables to ${TMPPDIR}/debugvars for easy debugging"
BASEDIR=$(pwd)
cat > ${TMPPDIR}/debugvars <<DBGSCRIPT
# debug vars, just 'source ${TMPPDIR}/debugvars'
export TOKDIR="${BASEDIR}/${TOKDIR}"
export TMPPDIR="${BASEDIR}/${TMPPDIR}"
export OPENSSL_CONF="${BASEDIR}/openssl.cnf"
export PKCS11_PROVIDER_MODULE="${PKCS11_PROVIDER_MODULE}"
DBGSCRIPT

if [ "$TEST_SETUP_SKIP_KEYS" != "1" ]; then
    title LINE "Creating new Self Sign CA"
    let "SERIAL+=1"
    certutil -S -s "CN=Issuer" -n selfCA -x -t "C,C,C" \
        -m ${SERIAL} -1 -2 -5 --keyUsage certSigning,crlSigning \
        --nsCertType sslCA,smimeCA,objectSigningCA \
        -f ${PINFILE} -d ${TOKDIR} -z ${SEEDFILE} >/dev/null 2>&1 <<CERTSCRIPT
y

n
CERTSCRIPT

    # RSA
    title LINE  "Creating Certificate request for 'My Test Cert'"
    certutil -R -s "CN=My Test Cert, O=PKCS11 Provider" -o ${TSTCRT}.req \
                -d ${TOKDIR} -f ${PINFILE} -z ${SEEDFILE} >/dev/null 2>&1
    let "SERIAL+=1"
    certutil -C -m ${SERIAL} -i ${TSTCRT}.req -o ${TSTCRT} -c selfCA \
                -d ${TOKDIR} -f ${PINFILE} >/dev/null 2>&1
    certutil -A -n testCert -i ${TSTCRT} -t "u,u,u" -d ${TOKDIR} \
                -f ${PINFILE} >/dev/null 2>&1

    KEYID=`certutil -K -d ${TOKDIR} -f ${PINFILE} |grep 'testCert'| cut -b 15-54`
    URIKEYID=""
    for (( i=0; i<${#KEYID}; i+=2 )); do
        line=`echo "${KEYID:$i:2}"`
        URIKEYID="$URIKEYID%$line"
    done

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

    # ECC
    title LINE  "Creating Certificate request for 'My EC Cert'"
    certutil -R -s "CN=My EC Cert, O=PKCS11 Provider" -k ec -q nistp256 \
                -o ${ECCRT}.req -d ${TOKDIR} -f ${PINFILE} -z ${SEEDFILE} >/dev/null 2>&1
    let "SERIAL+=1"
    certutil -C -m ${SERIAL} -i ${ECCRT}.req -o ${ECCRT} -c selfCA \
                -d ${TOKDIR} -f ${PINFILE} >/dev/null 2>&1
    certutil -A -n ecCert -i ${ECCRT} -t "u,u,u" \
                -d ${TOKDIR} -f ${PINFILE} >/dev/null 2>&1

    KEYID=`certutil -K -d ${TOKDIR} -f ${PINFILE} |grep 'ecCert'| cut -b 15-54`
    URIKEYID=""
    for (( i=0; i<${#KEYID}; i+=2 )); do
        line=`echo "${KEYID:$i:2}"`
        URIKEYID="$URIKEYID%$line"
    done

    ECBASEURI="pkcs11:id=${URIKEYID}"
    ECPUBURI="pkcs11:type=public;id=${URIKEYID}"
    ECPRIURI="pkcs11:type=private;id=${URIKEYID}"

    title LINE  "Creating Certificate request for 'My Peer EC Cert'"
    certutil -R -s "CN=My Peer EC Cert, O=PKCS11 Provider" \
                -k ec -q nistp256 -o ${ECPEERCRT}.req \
                -d ${TOKDIR} -f ${PINFILE} -z ${SEEDFILE} >/dev/null 2>&1
    let "SERIAL+=1"
    certutil -C -m ${SERIAL} -i ${ECPEERCRT}.req -o ${ECPEERCRT} \
                -c selfCA -d ${TOKDIR} -f ${PINFILE} >/dev/null 2>&1
    certutil -A -n ecPeerCert -i ${ECPEERCRT} -t "u,u,u" \
                -d ${TOKDIR} -f ${PINFILE} >/dev/null 2>&1

    KEYID=`certutil -K -d ${TOKDIR} -f ${PINFILE} |grep 'ecPeerCert'| cut -b 15-54`
    URIKEYID=""
    for (( i=0; i<${#KEYID}; i+=2 )); do
        line=`echo "${KEYID:$i:2}"`
        URIKEYID="$URIKEYID%$line"
    done

    ECPEERBASEURI="pkcs11:id=${URIKEYID}"
    ECPEERPUBURI="pkcs11:type=public;id=${URIKEYID}"
    ECPEERPRIURI="pkcs11:type=private;id=${URIKEYID}"

    title LINE "EC PKCS11 URIS"
    echo "${ECBASEURI}"
    echo "${ECPUBURI}"
    echo "${ECPRIURI}"
    echo "${ECPEERBASEURI}"
    echo "${ECPEERPUBURI}"
    echo "${ECPEERPRIURI}"
    echo ""

    title PARA "Show contents of softoken"
    echo " ----------------------------------------------------------------------------------------------------"
    certutil -L -d ${TOKDIR}
    certutil -K -d ${TOKDIR} -f ${PINFILE}
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
fi

title LINE "Set up environment variables"
export OPENSSL_CONF="${BASEDIR}/openssl.cnf"

title ENDSECTION
