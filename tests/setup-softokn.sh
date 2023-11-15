#!/bin/bash -e
# Copyright (C) 2022 Simo Sorce <simo@redhat.com>
# SPDX-License-Identifier: Apache-2.0

source "${TESTSSRCDIR}/helpers.sh"

if ! command -v certutil &> /dev/null
then
    echo "NSS's certutil command is required"
    exit 0
fi

title SECTION "Set up testing system"

TMPPDIR="${TESTBLDDIR}/tmp.softokn"
if [ -d "${TMPPDIR}" ]; then
    rm -fr "${TMPPDIR}"
fi
mkdir "${TMPPDIR}"

PINVALUE="12345678"
PINFILE="${TMPPDIR}/pinfile.txt"
echo ${PINVALUE} > "${PINFILE}"

#RANDOM data
SEEDFILE="${TMPPDIR}/noisefile.bin"
dd if=/dev/urandom of="${SEEDFILE}" bs=2048 count=1 >/dev/null 2>&1
RAND64FILE="${TMPPDIR}/64krandom.bin"
dd if=/dev/urandom of="${RAND64FILE}" bs=2048 count=32 >/dev/null 2>&1

# Create brand new tokens and certs
TOKDIR="$TMPPDIR/tokens"
if [ -d "${TOKDIR}" ]; then
    rm -fr "${TOKDIR}"
fi
mkdir "${TOKDIR}"

SERIAL=0

title LINE "Creating new NSS Database"
certutil -N -d "${TOKDIR}" -f "${PINFILE}"

title LINE "Creating new Self Sign CA"
((SERIAL+=1))
certutil -S -s "CN=Issuer" -n selfCA -x -t "C,C,C" \
    -m "${SERIAL}" -1 -2 -5 --keyUsage certSigning,crlSigning \
    --nsCertType sslCA,smimeCA,objectSigningCA \
    -f "${PINFILE}" -d "${TOKDIR}" -z "${SEEDFILE}" >/dev/null 2>&1 <<CERTSCRIPT
y

n
CERTSCRIPT

# RSA
TSTCRT="${TMPPDIR}/testcert"
TSTCRTN="testCert"
title LINE  "Creating Certificate request for 'My Test Cert'"
certutil -R -s "CN=My Test Cert, O=PKCS11 Provider" -o "${TSTCRT}.req" \
            -d "${TOKDIR}" -f "${PINFILE}" -z "${SEEDFILE}" >/dev/null 2>&1
((SERIAL+=1))
certutil -C -m "${SERIAL}" -i "${TSTCRT}.req" -o "${TSTCRT}.crt" -c selfCA \
            -d "${TOKDIR}" -f "${PINFILE}" >/dev/null 2>&1
certutil -A -n "${TSTCRTN}" -i "${TSTCRT}.crt" -t "u,u,u" -d "${TOKDIR}" \
            -f "${PINFILE}" >/dev/null 2>&1

KEYID=$(certutil -K -d "${TOKDIR}" -f "${PINFILE}" |grep "${TSTCRTN}"| cut -b 15-54)
URIKEYID=""
for (( i=0; i<${#KEYID}; i+=2 )); do
    line="${KEYID:$i:2}"
    URIKEYID="$URIKEYID%$line"
done

BASEURIWITHPIN="pkcs11:id=${URIKEYID};pin-value=${PINVALUE}"
BASEURI="pkcs11:id=${URIKEYID}"
PUBURI="pkcs11:type=public;id=${URIKEYID}"
PRIURI="pkcs11:type=private;id=${URIKEYID}"
CRTURI="pkcs11:type=cert;object=${TSTCRTN}"

title LINE "RSA PKCS11 URIS"
echo "${BASEURIWITHPIN}"
echo "${BASEURI}"
echo "${PUBURI}"
echo "${PRIURI}"
echo "${CRTURI}"
echo ""

# ECC
ECCRT="${TMPPDIR}/eccert"
ECCRTN="ecCert"
title LINE  "Creating Certificate request for 'My EC Cert'"
certutil -R -s "CN=My EC Cert, O=PKCS11 Provider" -k ec -q nistp256 \
            -o "${ECCRT}.req" -d "${TOKDIR}" -f "${PINFILE}" -z "${SEEDFILE}" >/dev/null 2>&1
((SERIAL+=1))
certutil -C -m "${SERIAL}" -i "${ECCRT}.req" -o "${ECCRT}.crt" -c selfCA \
            -d "${TOKDIR}" -f "${PINFILE}" >/dev/null 2>&1
certutil -A -n "${ECCRTN}" -i "${ECCRT}.crt" -t "u,u,u" \
            -d "${TOKDIR}" -f "${PINFILE}" >/dev/null 2>&1

KEYID=$(certutil -K -d "${TOKDIR}" -f "${PINFILE}" |grep "${ECCRTN}"| cut -b 15-54)
URIKEYID=""
for (( i=0; i<${#KEYID}; i+=2 )); do
    line="${KEYID:$i:2}"
    URIKEYID="$URIKEYID%$line"
done

ECBASEURIWITHPIN="pkcs11:id=${URIKEYID};pin-value=${PINVALUE}"
ECBASEURI="pkcs11:id=${URIKEYID}"
ECPUBURI="pkcs11:type=public;id=${URIKEYID}"
ECPRIURI="pkcs11:type=private;id=${URIKEYID}"
ECCRTURI="pkcs11:type=cert;object=${ECCRTN}"

title LINE  "Creating Certificate request for 'My Peer EC Cert'"
ECPEERCRT="${TMPPDIR}/ecpeercert"
ECPEERCRTN="ecPeerCert"
certutil -R -s "CN=My Peer EC Cert, O=PKCS11 Provider" \
            -k ec -q nistp256 -o "${ECPEERCRT}.req" \
            -d "${TOKDIR}" -f "${PINFILE}" -z "${SEEDFILE}" >/dev/null 2>&1
((SERIAL+=1))
certutil -C -m "${SERIAL}" -i "${ECPEERCRT}.req" -o "${ECPEERCRT}.crt" \
            -c selfCA -d "${TOKDIR}" -f "${PINFILE}" >/dev/null 2>&1
certutil -A -n "${ECPEERCRTN}" -i "${ECPEERCRT}.crt" -t "u,u,u" \
            -d "${TOKDIR}" -f "${PINFILE}" >/dev/null 2>&1

KEYID=$(certutil -K -d "${TOKDIR}" -f "${PINFILE}" |grep "${ECPEERCRTN}"| cut -b 15-54)
URIKEYID=""
for (( i=0; i<${#KEYID}; i+=2 )); do
    line="${KEYID:$i:2}"
    URIKEYID="$URIKEYID%$line"
done

ECPEERBASEURI="pkcs11:id=${URIKEYID}"
ECPEERPUBURI="pkcs11:type=public;id=${URIKEYID}"
ECPEERPRIURI="pkcs11:type=private;id=${URIKEYID}"
ECPEERCRTURI="pkcs11:type=cert;object=${ECPEERCRTN}"

title LINE "EC PKCS11 URIS"
echo "${ECBASEURIWITHPIN}"
echo "${ECBASEURI}"
echo "${ECPUBURI}"
echo "${ECPRIURI}"
echo "${ECCRTURI}"
echo "${ECPEERBASEURI}"
echo "${ECPEERPUBURI}"
echo "${ECPEERPRIURI}"
echo "${ECPEERCRTURI}"
echo ""

title PARA "Show contents of softoken"
echo " ----------------------------------------------------------------------------------------------------"
certutil -L -d "${TOKDIR}"
certutil -K -d "${TOKDIR}" -f "${PINFILE}"
echo " ----------------------------------------------------------------------------------------------------"

title PARA "Output configurations"
OPENSSL_CONF=${TMPPDIR}/openssl.cnf

title LINE "Generate openssl config file"
sed -e "s|@libtoollibs@|${LIBSPATH}|g" \
    -e "s|@testsblddir@|${TESTBLDDIR}|g" \
    -e "s|@testsdir@|${TMPPDIR}|g" \
    -e "s|@SHARED_EXT@|${SHARED_EXT}|g" \
    -e "s|@PINFILE@|${PINFILE}|g" \
    "${TESTSSRCDIR}/openssl.cnf.in" > "${OPENSSL_CONF}"

title LINE "Export tests variables to ${TMPPDIR}/testvars"
cat > "${TMPPDIR}/testvars" <<DBGSCRIPT
export PKCS11_PROVIDER_DEBUG="file:${TMPPDIR}/p11prov-debug.log"
export PKCS11_PROVIDER_MODULE="${SOFTOKNPATH%%/}/libsoftokn3${SHARED_EXT}"
export OPENSSL_CONF="${OPENSSL_CONF}"
export TESTSSRCDIR="${TESTSSRCDIR}"
export TESTBLDDIR="${TESTBLDDIR}"
export PINFILE="${PINFILE}"

export TOKDIR="${TOKDIR}"
export TMPPDIR="${TMPPDIR}"
export PINVALUE="${PINVALUE}"
export SEEDFILE="${TMPPDIR}/noisefile.bin"
export RAND64FILE="${TMPPDIR}/64krandom.bin"

export BASEURIWITHPIN="${BASEURIWITHPIN}"
export BASEURI="${BASEURI}"
export PUBURI="${PUBURI}"
export PRIURI="${PRIURI}"
export CRTURI="${CRTURI}"

export ECBASEURIWITHPIN="${ECBASEURIWITHPIN}"
export ECBASEURI="${ECBASEURI}"
export ECPUBURI="${ECPUBURI}"
export ECPRIURI="${ECPRIURI}"
export ECCRTURI="${ECCRTURI}"

export ECPEERBASEURI="${ECPEERBASEURI}"
export ECPEERPUBURI="${ECPEERPUBURI}"
export ECPEERPRIURI="${ECPEERPRIURI}"
export ECPEERCRTURI="${ECPEERCRTURI}"

DBGSCRIPT
gen_unsetvars

title ENDSECTION
