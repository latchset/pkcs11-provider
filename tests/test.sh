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
echo "KEY ID: ${KEYID} URI ID: ${URIKEYID}"

PUBURI="pkcs11:type=public;id=${URIKEYID};pin-value=${PINVALUE}"

echo "Export Public key to a file"
openssl pkey -in $PUBURI -pubin -pubout -out ${TSTCRT}.pub

exit 0
