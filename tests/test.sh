#!/bin/bash -e
# Copyright (C) 2022 Simo Sorce <simo@redhat.com>
# SPDX-License-Identifier: Apache-2.0

ossl()
{
    echo openssl $*

    eval openssl $1
}

############################## MAIN ##############################

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

if [ "$TEST_RSAPSS" = "1" ]; then
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
fi

if [ "$TEST_ECC_SHA2" = "1" ]; then
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
fi

echo "Super Secret" > ${TMPPDIR}/secret.txt
if [ "$TEST_OAEP_SHA2" = "1" ]; then
    title PARA "Encrypt and decrypt with RSA OAEP"
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
fi

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

if [ "$TEST_ECC_SHA2" = "1" ]; then
    title PARA "ECDH Exchange"
    ossl '
    pkeyutl -derive -inkey ${ECBASEURI}
                    -peerkey ${ECPEERPUBURI}
                    -out ${TMPPDIR}/secret.ecdh.bin'
fi

if [ "$TEST_HKDF" = "1" ]; then
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
fi

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

title PARA "Test CSR generation from private keys"
ossl '
req -new -batch -key "${PRIURI}" -out ${TMPPDIR}/rsa_csr.pem'
if [ "$TEST_ECC_SHA2" = "1" ]; then
    ossl '
    req -new -batch -key "${ECPRIURI}" -out ${TMPPDIR}/ecdsa_csr.pem'
fi

title PARA "Test Digests"
# Due to what seems a bug (https://github.com/openssl/openssl/issues/19662)
# inOpenSSL 3.x, using openssl dgst is not very useful, so we just test one
# common digest and defer to a custom test for digests until we have a fix.
dgst="sha256"
ossl 'dgst -${dgst} -out ${TMPPDIR}/dgst-${dgst}.ossl.txt ${TMPPDIR}/64krandom.bin'
ossl 'dgst -${dgst} -provider=pkcs11 -propquery "provider=pkcs11" -out ${TMPPDIR}/dgst-${dgst}.prov.txt ${TMPPDIR}/64krandom.bin'
OSSL_DGST=`cat ${TMPPDIR}/dgst-${dgst}.ossl.txt | cut -d= -f2`
PROV_DGST=`cat ${TMPPDIR}/dgst-${dgst}.prov.txt | cut -d= -f2`
if [ "${OSSL_DGST}" != "${PROV_DGST}" ]; then
    echo "${dgst} digest produced with provider does not match openssl produced one"
    echo "${PROV_DGST} != ${OSSL_DGST}"
    exit 1
fi

exit 0
