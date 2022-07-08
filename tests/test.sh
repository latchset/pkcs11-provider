#!/bin/bash -e

if ! command -v certutil &> /dev/null
then
    echo "NSS's certutil command is required"
    exit -1
fi

TOKDIR="tokens"
PINVALUE="12345678"
PINFILE="${TOKDIR}/pinfile.txt"

TMPDIR="tmp"
TSTCRT="${TMPDIR}/testcert.crt"
SEEDFILE="${TMPDIR}/noisefile.bin"

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

    if [ -d ${TMPDIR} ]; then
        rm -fr ${TMPDIR}
    fi
    mkdir ${TMPDIR}

    dd if=/dev/urandom of=${SEEDFILE} bs=2048 count=1 >/dev/null 2>&1
    echo ${PINVALUE} > ${PINFILE}

    title LINE "Creating new NSS Database"
    certutil -N -d ${TOKDIR} -f ${PINFILE}

    title LINE "Creating new Self Sign CA"
    certutil -S -s "CN=Issuer" -n selfCA -x -t "C,C,C" \
        -m 1 -1 -2 -5 --keyUsage certSigning,crlSigning \
        --nsCertType sslCA,smimeCA,objectSigningCA \
        -f ${PINFILE} -d ${TOKDIR} -z ${SEEDFILE} >/dev/null 2>&1 <<CERTSCRIPT
y

n
CERTSCRIPT

    title LINE  "Creating Certificate request for 'My Test Cert'"
    certutil -R -s "CN=My Test Cert, O=PKCS11 Provider" -o ${TSTCRT}.req -d ${TOKDIR} -f ${PINFILE} -z ${SEEDFILE} >/dev/null 2>&1
    certutil -C -m 2 -i ${TSTCRT}.req -o ${TSTCRT} -c selfCA -d ${TOKDIR} -f ${PINFILE} >/dev/null 2>&1
    certutil -A -n testCert -i ${TSTCRT} -t "u,u,u" -d ${TOKDIR} -f ${PINFILE} >/dev/null 2>&1

    title PARA "Show contents of softoken"
    echo " ----------------------------------------------------------------------------------------------------"
    certutil -L -d ${TOKDIR}
    certutil -K -d ${TOKDIR} -f ${PINFILE}
    echo " ----------------------------------------------------------------------------------------------------"

    KEYID=`certutil -K -d ${TOKDIR} -f ${PINFILE} |grep 'testCert'| cut -b 15-54`
    URIKEYID=""
    for (( i=0; i<${#KEYID}; i+=2 )); do
        line=`echo "${KEYID:$i:2}"`
        URIKEYID="$URIKEYID%$line"
    done

    BASEURI="pkcs11:id=${URIKEYID};pin-value=${PINVALUE}"
    PUBURI="pkcs11:type=public;id=${URIKEYID};pin-value=${PINVALUE}"
    PRIURI="pkcs11:type=private;id=${URIKEYID};pin-value=${PINVALUE}"
    title LINE "PKCS11 URI"
    echo "${BASEURI}"
    echo ""

    title LINE "Export variables to ${TMPDIR}/debugvars for easy debugging"
    cat > ${TMPDIR}/debugvars <<DBGSCRIPT
# debug vars, just 'source ${TMPDIR}/debugvars'
TMPDIR=$(dirname "$0")
BASEDIR=$(dirname "$TMPDIR")

export TOKDIR="${BASEDIR}/${TOKDIR}"
export TMPDIR=${TMPDIR}
export OPENSSL_CONF="${BASEDIR}/openssl.cnf"

export PINVALUE=${PINVALUE}
export PINFILE="${BASEDIR}/${PINFILE}"
export TSTCRT="${BASEDIR}/${TSTCRT}"
export SEEDFILE="${BASEDIR}/${SEEDFILE}"

export BASEURI=${BASEURI}
export PUBURI=${PUBURI}
export PRIURI=${PRIURI}
DBGSCRIPT

    title ENDSECTION
}

ossl()
{
    echo "$*"

    eval openssl $1
}

############################## MAIN ##############################

setup

title PARA "Export Public key to a file"
ossl 'pkey -in $BASEURI -pubin -pubout -out ${TSTCRT}.pub'
ossl 'pkey -in $PUBURI -pubin -pubout -out ${TSTCRT}.pub'
ossl 'pkey -in $PRIURI -pubin -pubout -out ${TSTCRT}.pub'

title PARA "Raw Sign check error"
dd if=/dev/urandom of=${TMPDIR}/64Brandom.bin bs=64 count=1 >/dev/null 2>&1
FAIL=0
ossl '
pkeyutl -sign -inkey "${BASEURI}"
              -pkeyopt pad-mode:none
              -in ${TMPDIR}/64Brandom.bin
              -out ${TMPDIR}/raw-sig.bin' || FAIL=1
if [ $FAIL -eq 0 ]; then
    echo "Raw signature should not allow data != modulus size"
    exit 1
fi
# unfortunately pkeyutl simply does not make it possible to sign anything
# that is bigger than a hash, which means we'd need a very small RSA key
# to really check a raw signature through pkeyutl

title PARA "Sign and Verify with provided Hash"
ossl 'dgst -sha256 -binary -out ${TMPDIR}/sha256.bin ${SEEDFILE}'
ossl '
pkeyutl -sign -inkey "${BASEURI}"
              -in ${TMPDIR}/sha256.bin
              -out ${TMPDIR}/sha256-sig.bin'

ossl '
pkeyutl -verify -inkey "${PRIURI}"
                -in ${TMPDIR}/sha256.bin
                -sigfile ${TMPDIR}/sha256-sig.bin'
ossl '
pkeyutl -verify -inkey "${PUBURI}"
                -pubin
                -in ${TMPDIR}/sha256.bin
                -sigfile ${TMPDIR}/sha256-sig.bin'

title PARA "DigestSign and DigestVerify"
dd if=/dev/urandom of=${TMPDIR}/64krandom.bin bs=2048 count=32 >/dev/null 2>&1
ossl '
pkeyutl -sign -inkey "${BASEURI}"
              -digest sha256
              -in ${TMPDIR}/64krandom.bin
              -rawin
              -out ${TMPDIR}/sha256-dgstsig.bin'
ossl '
pkeyutl -verify -inkey "${BASEURI}"
                -digest sha256
                -in ${TMPDIR}/64krandom.bin
                -rawin
                -sigfile ${TMPDIR}/sha256-dgstsig.bin'
ossl '
pkeyutl -verify -inkey "${PUBURI}"
                -pubin
                -digest sha256
                -in ${TMPDIR}/64krandom.bin
                -rawin
                -sigfile ${TMPDIR}/sha256-dgstsig.bin'

title PARA "PSS DigestSign and DigestVerify"
ossl '
pkeyutl -sign -inkey "${BASEURI}"
              -digest sha256
              -pkeyopt pad-mode:pss
              -pkeyopt mgf1-digest:sha256
              -pkeyopt saltlen:digest
              -in ${TMPDIR}/64krandom.bin
              -rawin
              -out ${TMPDIR}/sha256-dgstsig.bin'
ossl '
pkeyutl -verify -inkey "${BASEURI}"
                -digest sha256
                -pkeyopt pad-mode:pss
                -pkeyopt mgf1-digest:sha256
                -pkeyopt saltlen:digest
                -in ${TMPDIR}/64krandom.bin
                -rawin
                -sigfile ${TMPDIR}/sha256-dgstsig.bin'
title LINE "Re-verify using OpenSSL defult provider"
#(-pubin causes us to export a public key and OpenSSL to import it in the default provider)
ossl '
pkeyutl -verify -inkey "${PUBURI}"
                -pubin
                -digest sha256
                -pkeyopt pad-mode:pss
                -pkeyopt mgf1-digest:sha256
                -pkeyopt saltlen:digest
                -in ${TMPDIR}/64krandom.bin
                -rawin
                -sigfile ${TMPDIR}/sha256-dgstsig.bin'

title PARA "Encrypt and decrypt"
echo "Super Secret" > ${TMPDIR}/secret.txt
# Let openssl encrypt by importing the public key
ossl '
pkeyutl -encrypt -inkey "${BASEURI}"
                 -pubin
                 -pkeyopt pad-mode:oaep
                 -pkeyopt digest:sha256
                 -pkeyopt mgf1-digest:sha256
                 -in ${TMPDIR}/secret.txt
                 -out ${TMPDIR}/secret.txt.enc'
ossl '
pkeyutl -decrypt -inkey "${PRIURI}"
                 -pkeyopt pad-mode:oaep
                 -pkeyopt digest:sha256
                 -pkeyopt mgf1-digest:sha256
                 -in ${TMPDIR}/secret.txt.enc
                 -out ${TMPDIR}/secret.txt.dec'
diff ${TMPDIR}/secret.txt ${TMPDIR}/secret.txt.dec

title LINE "Now again all in the token"
ossl '
pkeyutl -encrypt -inkey "${PRIURI}"
                 -in ${TMPDIR}/secret.txt
                 -out ${TMPDIR}/secret.txt.enc2'
ossl '
pkeyutl -decrypt -inkey "${PRIURI}"
                 -in ${TMPDIR}/secret.txt.enc2
                 -out ${TMPDIR}/secret.txt.dec2'
diff ${TMPDIR}/secret.txt ${TMPDIR}/secret.txt.dec2

exit 0
