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

# Create brand new tokens and certs
if [ -d ${TOKDIR} ]; then
    rm -vfr ${TOKDIR}
fi
mkdir ${TOKDIR}

if [ -d ${TMPDIR} ]; then
    rm -vfr ${TMPDIR}
fi
mkdir ${TMPDIR}

dd if=/dev/urandom of=${SEEDFILE} bs=2048 count=1
echo ${PINVALUE} > ${PINFILE}

echo "Creating new NSS Database"
certutil -N -d ${TOKDIR} -f ${PINFILE}

echo "Creating new Self Sign CA"
certutil -S -s "CN=Issuer" -n selfCA -x -t "C,C,C" \
    -m 1 -1 -2 -5 --keyUsage certSigning,crlSigning \
    --nsCertType sslCA,smimeCA,objectSigningCA \
    -f ${PINFILE} -d ${TOKDIR} -z ${SEEDFILE} 2>&1 <<CERTSCRIPT
y

n
CERTSCRIPT

echo "Creating Certificate request for 'My Test Cert'"
certutil -R -s "CN=My Test Cert, O=PKCS11 Provider" -o ${TSTCRT}.req -d ${TOKDIR} -f ${PINFILE} -z ${SEEDFILE}
certutil -C -m 2 -i ${TSTCRT}.req -o ${TSTCRT} -c selfCA -d ${TOKDIR} -f ${PINFILE}
certutil -A -n testCert -i ${TSTCRT} -t "u,u,u" -d ${TOKDIR} -f ${PINFILE}

echo "Show contents of token"
certutil -L -d ${TOKDIR}
certutil -K -d ${TOKDIR} -f ${PINFILE}

KEYID=`certutil -K -d ${TOKDIR} -f ${PINFILE} |grep 'testCert'| cut -b 15-54`
URIKEYID=""
for (( i=0; i<${#KEYID}; i+=2 )); do
    line=`echo "${KEYID:$i:2}"`
    URIKEYID="$URIKEYID%$line"
done

BASEURI="pkcs11:id=${URIKEYID};pin-value=${PINVALUE}"
PUBURI="pkcs11:type=public;id=${URIKEYID};pin-value=${PINVALUE}"
PRIURI="pkcs11:type=private;id=${URIKEYID};pin-value=${PINVALUE}"
echo "PKCS11 URI: ${BASEURI}"

echo "## Export Public key to a file"
openssl pkey -in $BASEURI -pubin -pubout -out ${TSTCRT}.pub
openssl pkey -in $PUBURI -pubin -pubout -out ${TSTCRT}.pub
openssl pkey -in $PRIURI -pubin -pubout -out ${TSTCRT}.pub

echo "## Raw Sign check error"
dd if=/dev/urandom of=${TMPDIR}/64Brandom.bin bs=64 count=1
FAIL=0
openssl pkeyutl -sign -pkeyopt pad-mode:none -in ${TMPDIR}/64Brandom.bin -out ${TMPDIR}/raw-sig.bin -inkey "${BASEURI}" || FAIL=1
if [ $FAIL -eq 0 ]; then
    echo "Raw signature should not allow data != modulus size"
    exit 1
fi
# unfortunately pkeyutl simply does not make it possible to sign anything
# that is bigger than a hash, which means we'd need a very small RSA key
# to really check a raw signature through pkeyutl

echo "## Sign and Verify with provided Hash"
openssl dgst -sha256 -binary ${SEEDFILE} > ${TMPDIR}/sha256.bin
openssl pkeyutl -sign -in ${TMPDIR}/sha256.bin -out ${TMPDIR}/sha256-sig.bin -inkey "${BASEURI}"
openssl pkeyutl -verify -in ${TMPDIR}/sha256.bin -sigfile ${TMPDIR}/sha256-sig.bin -inkey "${PRIURI}"
openssl pkeyutl -verify -in ${TMPDIR}/sha256.bin -sigfile ${TMPDIR}/sha256-sig.bin -pubin -inkey "${PUBURI}"

echo "## DigestSign and DigestVerify"
dd if=/dev/urandom of=${TMPDIR}/64krandom.bin bs=2048 count=32
openssl pkeyutl -sign -in ${TMPDIR}/64krandom.bin -rawin -digest sha256 -out ${TMPDIR}/sha256-dgstsig.bin -inkey "${BASEURI}"
openssl pkeyutl -verify -in ${TMPDIR}/64krandom.bin -rawin -digest sha256 -sigfile ${TMPDIR}/sha256-dgstsig.bin -pubin -inkey "${PUBURI}"

exit 0
