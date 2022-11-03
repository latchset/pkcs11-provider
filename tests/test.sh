#!/bin/bash -e
# Copyright (C) 2022 Simo Sorce <simo@redhat.com>
# SPDX-License-Identifier: Apache-2.0

if ! command -v certutil &> /dev/null
then
    echo "NSS's certutil command is required"
    exit -1
fi

TOKDIR="tokens"
PINVALUE="12345678"
PINFILE="${TOKDIR}/pinfile.txt"

TMPPDIR="tmp"
TSTCRT="${TMPPDIR}/testcert.crt"
ECCRT="${TMPPDIR}/eccert.crt"
ECPEERCRT="${TMPPDIR}/ecpeercert.crt"
SEEDFILE="${TMPPDIR}/noisefile.bin"
SERIAL=0

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

setup()
{
    title SECTION "Set up testing system"

    # Create brand new tokens and certs
    if [ -d ${TOKDIR} ]; then
        rm -fr ${TOKDIR}
    fi
    mkdir ${TOKDIR}

    if [ -d ${TMPPDIR} ]; then
        rm -fr ${TMPPDIR}
    fi
    mkdir ${TMPPDIR}

    dd if=/dev/urandom of=${SEEDFILE} bs=2048 count=1 >/dev/null 2>&1
    echo ${PINVALUE} > ${PINFILE}

    title LINE "Creating new NSS Database"
    certutil -N -d ${TOKDIR} -f ${PINFILE}

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

    title LINE "Export variables to ${TMPPDIR}/debugvars for easy debugging"
    BASEDIR=$(pwd)
    cat > ${TMPPDIR}/debugvars <<DBGSCRIPT
# debug vars, just 'source ${TMPPDIR}/debugvars'
export TOKDIR="${BASEDIR}/${TOKDIR}"
export TMPPDIR="${BASEDIR}/${TMPPDIR}"
export OPENSSL_CONF="${BASEDIR}/openssl.cnf"

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
DBGSCRIPT

    OPENSSL_CONF="${BASEDIR}/openssl.cnf"

    title ENDSECTION
}

ossl()
{
    echo openssl $*

    eval openssl $1
}

############################## MAIN ##############################

setup

title PARA "Export Public key to a file"
ossl 'pkey -in $BASEURI -pubin -pubout -out ${TSTCRT}.pub'
title LINE "Export Public key to a file (pub-uri)"
ossl 'pkey -in $PUBURI -pubin -pubout -out ${TSTCRT}.pub'
title LINE "Export Public key to a file (with pin)"
ossl 'pkey -in $BASEURIWITHPIN -pubin -pubout -out ${TSTCRT}.pub'

title PARA "Export Public check error"
FAIL=0
ossl 'pkey -in pkcs11:id=%de%ad -pubin
           -pubout -out ${TSTCRT}-invlid.pub' || FAIL=1
if [ $FAIL -eq 0 ]; then
    echo "Invalid pkcs11 uri resulted in no error exporting key"
    exit 1
fi

title PARA "Export EC Public key to a file"
ossl 'pkey -in $ECPUBURI -pubin -pubout -out ${ECCRT}.pub'

title PARA "Raw Sign check error"
dd if=/dev/urandom of=${TMPPDIR}/64Brandom.bin bs=64 count=1 >/dev/null 2>&1
FAIL=0
ossl '
pkeyutl -sign -inkey "${BASEURI}"
              -pkeyopt pad-mode:none
              -in ${TMPPDIR}/64Brandom.bin
              -out ${TMPPDIR}/raw-sig.bin' || FAIL=1
if [ $FAIL -eq 0 ]; then
    echo "Raw signature should not allow data != modulus size"
    exit 1
fi
# unfortunately pkeyutl simply does not make it possible to sign anything
# that is bigger than a hash, which means we'd need a very small RSA key
# to really check a raw signature through pkeyutl

title PARA "Sign and Verify with provided Hash and RSA"
ossl 'dgst -sha256 -binary -out ${TMPPDIR}/sha256.bin ${SEEDFILE}'
ossl '
pkeyutl -sign -inkey "${PRIURI}"
              -in ${TMPPDIR}/sha256.bin
              -out ${TMPPDIR}/sha256-sig.bin'

ossl '
pkeyutl -verify -inkey "${PUBURI}"
                -pubin
                -in ${TMPPDIR}/sha256.bin
                -sigfile ${TMPPDIR}/sha256-sig.bin'

title PARA "Sign and Verify with provided Hash and EC"
ossl '
pkeyutl -sign -inkey "${ECBASEURI}"
              -in ${TMPPDIR}/sha256.bin
              -out ${TMPPDIR}/sha256-ecsig.bin'

ossl '
pkeyutl -verify -inkey "${ECBASEURI}" -pubin
                -in ${TMPPDIR}/sha256.bin
                -sigfile ${TMPPDIR}/sha256-ecsig.bin'


dd if=/dev/urandom of=${TMPPDIR}/64krandom.bin bs=2048 count=32 >/dev/null 2>&1
title PARA "DigestSign and DigestVerify with RSA"
ossl '
pkeyutl -sign -inkey "${BASEURI}"
              -digest sha256
              -in ${TMPPDIR}/64krandom.bin
              -rawin
              -out ${TMPPDIR}/sha256-dgstsig.bin'
ossl '
pkeyutl -verify -inkey "${BASEURI}" -pubin
                -digest sha256
                -in ${TMPPDIR}/64krandom.bin
                -rawin
                -sigfile ${TMPPDIR}/sha256-dgstsig.bin'
ossl '
pkeyutl -verify -inkey "${PUBURI}"
                -pubin
                -digest sha256
                -in ${TMPPDIR}/64krandom.bin
                -rawin
                -sigfile ${TMPPDIR}/sha256-dgstsig.bin'

title PARA "DigestSign and DigestVerify with RSA PSS"
ossl '
pkeyutl -sign -inkey "${BASEURI}"
              -digest sha256
              -pkeyopt pad-mode:pss
              -pkeyopt mgf1-digest:sha256
              -pkeyopt saltlen:digest
              -in ${TMPPDIR}/64krandom.bin
              -rawin
              -out ${TMPPDIR}/sha256-dgstsig.bin'
ossl '
pkeyutl -verify -inkey "${BASEURI}" -pubin
                -digest sha256
                -pkeyopt pad-mode:pss
                -pkeyopt mgf1-digest:sha256
                -pkeyopt saltlen:digest
                -in ${TMPPDIR}/64krandom.bin
                -rawin
                -sigfile ${TMPPDIR}/sha256-dgstsig.bin'
title LINE "Re-verify using OpenSSL default provider"
#(-pubin causes us to export a public key and OpenSSL to import it in the default provider)
ossl '
pkeyutl -verify -inkey "${PUBURI}"
                -pubin
                -digest sha256
                -pkeyopt pad-mode:pss
                -pkeyopt mgf1-digest:sha256
                -pkeyopt saltlen:digest
                -in ${TMPPDIR}/64krandom.bin
                -rawin
                -sigfile ${TMPPDIR}/sha256-dgstsig.bin'

title PARA "DigestSign and DigestVerify with ECC"
ossl '
pkeyutl -sign -inkey "${ECBASEURI}"
              -digest sha256
              -in ${TMPPDIR}/64krandom.bin
              -rawin
              -out ${TMPPDIR}/sha256-ecdgstsig.bin'
ossl '
pkeyutl -verify -inkey "${ECBASEURI}" -pubin
                -digest sha256
                -in ${TMPPDIR}/64krandom.bin
                -rawin
                -sigfile ${TMPPDIR}/sha256-ecdgstsig.bin'

title PARA "Encrypt and decrypt with RSA OAEP"
echo "Super Secret" > ${TMPPDIR}/secret.txt
# Let openssl encrypt by importing the public key
ossl '
pkeyutl -encrypt -inkey "${BASEURI}"
                 -pubin
                 -pkeyopt pad-mode:oaep
                 -pkeyopt digest:sha256
                 -pkeyopt mgf1-digest:sha256
                 -in ${TMPPDIR}/secret.txt
                 -out ${TMPPDIR}/secret.txt.enc'
ossl '
pkeyutl -decrypt -inkey "${PRIURI}"
                 -pkeyopt pad-mode:oaep
                 -pkeyopt digest:sha256
                 -pkeyopt mgf1-digest:sha256
                 -in ${TMPPDIR}/secret.txt.enc
                 -out ${TMPPDIR}/secret.txt.dec'
diff ${TMPPDIR}/secret.txt ${TMPPDIR}/secret.txt.dec

title LINE "Now again all in the token"
ossl '
pkeyutl -encrypt -inkey "${PUBURI}" -pubin
                 -in ${TMPPDIR}/secret.txt
                 -out ${TMPPDIR}/secret.txt.enc2'
ossl '
pkeyutl -decrypt -inkey "${PRIURI}"
                 -in ${TMPPDIR}/secret.txt.enc2
                 -out ${TMPPDIR}/secret.txt.dec2'
diff ${TMPPDIR}/secret.txt ${TMPPDIR}/secret.txt.dec2

title PARA "ECDH Exchange"
ossl '
pkeyutl -derive -inkey ${ECBASEURI}
                -peerkey ${ECPEERPUBURI}
                -out ${TMPPDIR}/secret.ecdh.bin'

title PARA "HKDF Derivation"
HKDF_HEX_SECRET=ffeeddccbbaa
HKDF_HEX_SALT=ffeeddccbbaa
HKDF_HEX_INFO=ffeeddccbbaa
ossl '
pkeyutl -derive -kdf HKDF -kdflen 48
                -pkeyopt md:SHA256
                -pkeyopt mode:EXTRACT_AND_EXPAND
                -pkeyopt hexkey:${HKDF_HEX_SECRET}
                -pkeyopt hexsalt:${HKDF_HEX_SALT}
                -pkeyopt hexinfo:${HKDF_HEX_INFO}
                -out ${TMPPDIR}/hkdf1-out-pkcs11.bin
                -propquery provider=pkcs11'
ossl '
pkeyutl -derive -kdf HKDF -kdflen 48
                -pkeyopt md:SHA256
                -pkeyopt mode:EXTRACT_AND_EXPAND
                -pkeyopt hexkey:${HKDF_HEX_SECRET}
                -pkeyopt hexsalt:${HKDF_HEX_SALT}
                -pkeyopt hexinfo:${HKDF_HEX_INFO}
                -out ${TMPPDIR}/hkdf1-out.bin'
diff ${TMPPDIR}/hkdf1-out-pkcs11.bin ${TMPPDIR}/hkdf1-out.bin

HKDF_HEX_SECRET=6dc3bcf529a350e0423befb3deef8aef78d912c4f1dc3e6e52bf61f681e40904
HKDF_SALT="I'm a Salt!"
HKDF_INFO="And I'm an Info?"
ossl '
pkeyutl -derive -kdf HKDF -kdflen 48
                -pkeyopt md:SHA256
                -pkeyopt mode:EXTRACT_AND_EXPAND
                -pkeyopt hexkey:${HKDF_HEX_SECRET}
                -pkeyopt salt:"${HKDF_SALT}"
                -pkeyopt info:"${HKDF_INFO}"
                -out ${TMPPDIR}/hkdf2-out-pkcs11.bin
                -propquery provider=pkcs11'
ossl '
pkeyutl -derive -kdf HKDF -kdflen 48
                -pkeyopt md:SHA256
                -pkeyopt mode:EXTRACT_AND_EXPAND
                -pkeyopt hexkey:${HKDF_HEX_SECRET}
                -pkeyopt salt:"${HKDF_SALT}"
                -pkeyopt info:"${HKDF_INFO}"
                -out ${TMPPDIR}/hkdf2-out.bin'
diff ${TMPPDIR}/hkdf2-out-pkcs11.bin ${TMPPDIR}/hkdf2-out.bin

title PARA "Test session support"
BASEURI="${BASEURI}" ./tsession

title PARA "Test Disallow Public Export"
FAIL=0
ORIG_OPENSSL_CONF=${OPENSSL_CONF}
sed "s/#pkcs11-module-allow-export/pkcs11-module-allow-export = 1/" ${OPENSSL_CONF} > ${OPENSSL_CONF}.noexport
OPENSSL_CONF=${OPENSSL_CONF}.noexport
ossl 'pkey -in $BASEURI -pubin -pubout -out ${TSTCRT}.pub.fail' || FAIL=1
if [ $FAIL -eq 0 ]; then
    echo "pkcs11 export should have failed, but actually succeeded"
    exit 1
fi
OPENSSL_CONF=${ORIG_OPENSSL_CONF}
rm -f ${OPENSSL_CONF}.noexport

exit 0
