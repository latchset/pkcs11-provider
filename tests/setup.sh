#!/bin/bash -ex
# Copyright (C) 2024 Simo Sorce <simo@redhat.com>
# SPDX-License-Identifier: Apache-2.0

source "${TESTSSRCDIR}/helpers.sh"

if [ $# -ne 1 ]; then
    echo "Usage setup.sh <tokentype>"
    exit 1
fi

TOKENTYPE=$1

# defaults -- overridden below or in the per-token setup
SUPPORT_ED25519=1
SUPPORT_ED448=1
SUPPORT_RSA_PKCS1_ENCRYPTION=1
SUPPORT_RSA_KEYGEN_PUBLIC_EXPONENT=1
SUPPORT_TLSFUZZER=1
SUPPORT_ALLOWED_MECHANISMS=0
SUPPORT_SYMMETRIC=1

# Ed448 requires OpenSC 0.26.0
OPENSC_VERSION=$(opensc-tool -i | grep OpenSC | sed -e "s/OpenSC 0\.\([0-9]*\).*/\1/")
if [[ "$OPENSC_VERSION" -le "25" ]]; then
    SUPPORT_ED448=0
fi

# FIPS Mode
if [[ "${PKCS11_PROVIDER_FORCE_FIPS_MODE}" = "1" || "$(cat /proc/sys/crypto/fips_enabled)" = "1" ]]; then
    # We can not use Edwards curves in FIPS mode
    SUPPORT_ED25519=0
    SUPPORT_ED448=0

    # The FIPS does not allow the RSA-PKCS1.5 encryption
    SUPPORT_RSA_PKCS1_ENCRYPTION=0

    # The FIPS does not allow to set custom public exponent during key
    # generation
    SUPPORT_RSA_KEYGEN_PUBLIC_EXPONENT=0

    # TLS Fuzzer does not work well in FIPS mode
    SUPPORT_TLSFUZZER=0

    # We also need additional configuration in openssl.cnf to assume the token
    # is FIPS token
    TOKENOPTIONS="pkcs11-module-assume-fips = true"

    # Force OpenSSL FIPS mode
    export OPENSSL_FORCE_FIPS_MODE=1

    # Force NSS softokn FIPS mode
    export NSS_FIPS=1

    # NSS softokn requires stronger PIN in FIPS mode
    PINVALUE="fo0m4nchU"
else
    PINVALUE="12345678"
fi

# Check if openssl supports skey
SUPPORT_SKEY=0
$OPENSSL skeyutl -h >/dev/null 2>&1 && SUPPORT_SKEY=1

# Temporary dir and Token data dir
TMPPDIR="${TESTBLDDIR}/${TOKENTYPE}"
TOKDIR="$TMPPDIR/tokens"
if [ -d "${TMPPDIR}" ]; then
    rm -fr "${TMPPDIR}"
fi
mkdir "${TMPPDIR}"
mkdir "${TOKDIR}"

PINFILE="${TMPPDIR}/pinfile.txt"
echo ${PINVALUE} > "${PINFILE}"

if [ "${TOKENTYPE}" == "softhsm" ]; then
    source "${TESTSSRCDIR}/softhsm-init.sh"
elif [ "${TOKENTYPE}" == "softokn" ]; then
    source "${TESTSSRCDIR}/softokn-init.sh"
elif [ "${TOKENTYPE}" == "kryoptic" ]; then
    source "${TESTSSRCDIR}/kryoptic-init.sh"
elif [ "${TOKENTYPE}" == "kryoptic.nss" ]; then
    source "${TESTSSRCDIR}/kryoptic.nss-init.sh"
else
    echo "Unknown token type: $1"
    exit 1
fi

if [[ "${PKCS11_PROVIDER_FORCE_FIPS_MODE}" = "1" ]]; then
    # temporarily suppress symmetric tests in FIPS mode as no FIPS provider
    # supports SKEYMGMT yet.
    SUPPORT_SKEY=0
    SUPPORT_SYMMETRIC=0
fi
if [[ "${SUPPORT_SKEY}" = "1" ]]; then
    if [[ "${SUPPORT_SYMMETRIC}" = "0" ]]; then
        TOKENOPTIONS="pkcs11-module-block-operations = cipher skeymgmt\n$TOKENOPTIONS"
    fi
fi

#RANDOM data
SEEDFILE="${TMPPDIR}/noisefile.bin"
dd if=/dev/urandom of="${SEEDFILE}" bs=2048 count=1 >/dev/null 2>&1
RAND64FILE="${TMPPDIR}/64krandom.bin"
dd if=/dev/urandom of="${RAND64FILE}" bs=2048 count=32 >/dev/null 2>&1

P11DEFLOGIN=("--login" "--pin=${PINVALUE}")

title LINE "Generate openssl config file"
export PKCS11_PROVIDER_MODULE=${P11LIB}
#export PKCS11SPY="${P11LIB}"
#export PKCS11_PROVIDER_MODULE=/usr/lib64/pkcs11/pkcs11-spy.so
export PKCS11_PROVIDER_DEBUG="file:${TMPPDIR}/p11prov-debug.log"
export OPENSSL_CONF=${TMPPDIR}/openssl.cnf
sed -e "s|@libtoollibs@|${LIBSPATH}|g" \
    -e "s|@testsblddir@|${TESTBLDDIR}|g" \
    -e "s|@testsdir@|${TMPPDIR}|g" \
    -e "s|@SHARED_EXT@|${SHARED_EXT}|g" \
    -e "s|@PINFILE@|${PINFILE}|g" \
    -e "s|##TOKENOPTIONS|${TOKENOPTIONS}|g" \
    "${TESTSSRCDIR}/openssl.cnf.in" > "${OPENSSL_CONF}"

# Serial = 1 is the CA
SERIAL=0

crt_selfsign() {
    LABEL=$1
    CN=$2
    KEYID=$3

    ((SERIAL+=1))

    CERTSUBJ="/CN=$CN/"
    SIGNKEY="pkcs11:object=$LABEL;token=$TOKENLABELURI;type=private"

    OPENSSL_CMD="x509
        -new -subj \"${CERTSUBJ}\" -days 365 -set_serial \"${SERIAL}\"
        -extensions v3_ca -extfile \"${OPENSSL_CONF}\"
        -out \"${TMPPDIR}/${LABEL}.crt\" -outform DER
        -signkey \"${SIGNKEY}\""

    ossl "${OPENSSL_CMD}" 2>&1
    ptool --write-object "${TMPPDIR}/${LABEL}.crt" --type=cert --id="$KEYID" \
          --label="$LABEL" 2>&1
}

title LINE "Creating new Self Sign CA"
KEYID='0000'
URIKEYID="%00%00"
CACRTN="caCert"
ptool --keypairgen --key-type="RSA:2048" --id="${KEYID}" \
      --label="${CACRTN}" 2>&1
crt_selfsign $CACRTN "Issuer" $KEYID

# convert the DER cert to PEM
CACRT_PEM="${TMPPDIR}/${CACRTN}.pem"
OPENSSL_CMD='x509
    -inform DER -in "${TMPPDIR}/${CACRTN}.crt"
    -outform PEM -out "$CACRT_PEM"'
ossl "$OPENSSL_CMD"

CABASEURIWITHPINVALUE="pkcs11:id=${URIKEYID}?pin-value=${PINVALUE}"
CABASEURIWITHPINSOURCE="pkcs11:id=${URIKEYID}?pin-source=file:${PINFILE}"
CABASEURI="pkcs11:id=${URIKEYID}"
CAPUBURI="pkcs11:type=public;id=${URIKEYID}"
CAPRIURI="pkcs11:type=private;id=${URIKEYID}"
CACRTURI="pkcs11:type=cert;object=${CACRTN}"

title LINE "RSA PKCS11 URIS"
echo "${CABASEURIWITHPINVALUE}"
echo "${CABASEURIWITHPINSOURCE}"
echo "${CABASEURI}"
echo "${CAPUBURI}"
echo "${CAPRIURI}"
echo "${CACRTURI}"
echo ""

ca_sign() {
    LABEL=$1
    CN=$2
    KEYID=$3
    SIGOPT=$4

    ((SERIAL+=1))

    CERTSUBJ="/O=PKCS11 Provider/CN=$CN/"
    SIGNKEY="pkcs11:object=$CACRTN;token=$TOKENLABELURI;type=private"
    CERTPUBKEY="pkcs11:object=$LABEL;token=$TOKENLABELURI;type=public"

    OPENSSL_CMD="x509
        -new -subj \"${CERTSUBJ}\" -days 365 -set_serial \"${SERIAL}\"
        -extensions v3_req -extfile \"${OPENSSL_CONF}\"
        -out \"${TMPPDIR}/${LABEL}.crt\" -outform DER
        -force_pubkey \"${CERTPUBKEY}\" -signkey \"${SIGNKEY}\""

    if [ "$SIGOPT" = "PSS" ]; then
        OPENSSL_CMD+=" -sigopt rsa_padding_mode:pss"
    elif [ "$SIGOPT" = "PSS-SHA256" ]; then
        OPENSSL_CMD+=" -sigopt rsa_padding_mode:pss -sigopt digest:sha256"
    fi

    ossl "${OPENSSL_CMD}" 2>&1
    ptool --write-object "${TMPPDIR}/${LABEL}.crt" --type=cert --id="$KEYID" \
          --label="$LABEL" 2>&1
}


# generate RSA key pair and self-signed certificate
KEYID='0001'
URIKEYID="%00%01"
TSTCRTN="testCert"

ptool --keypairgen --key-type="RSA:2048" --id="$KEYID" \
      --label="${TSTCRTN}" 2>&1
ca_sign "${TSTCRTN}" "My Test Cert" $KEYID

BASEURIWITHPINVALUE="pkcs11:id=${URIKEYID}?pin-value=${PINVALUE}"
BASEURIWITHPINSOURCE="pkcs11:id=${URIKEYID}?pin-source=file:${PINFILE}"
BASEURI="pkcs11:id=${URIKEYID}"
PUBURI="pkcs11:type=public;id=${URIKEYID}"
PRIURI="pkcs11:type=private;id=${URIKEYID}"
CRTURI="pkcs11:type=cert;object=${TSTCRTN}"

title LINE "RSA PKCS11 URIS"
echo "${BASEURIWITHPINVALUE}"
echo "${BASEURIWITHPINSOURCE}"
echo "${BASEURI}"
echo "${PUBURI}"
echo "${PRIURI}"
echo "${CRTURI}"
echo ""

# generate ECC key pair
KEYID='0002'
URIKEYID="%00%02"
ECCRTN="ecCert"

ptool --keypairgen --key-type="EC:secp256r1" --id="$KEYID" \
      --label="${ECCRTN}" 2>&1
ca_sign $ECCRTN "My EC Cert" $KEYID

ECBASEURIWITHPINVALUE="pkcs11:id=${URIKEYID}?pin-value=${PINVALUE}"
ECBASEURIWITHPINSOURCE="pkcs11:id=${URIKEYID}?pin-source=file:${PINFILE}"
ECBASEURI="pkcs11:id=${URIKEYID}"
ECPUBURI="pkcs11:type=public;id=${URIKEYID}"
ECPRIURI="pkcs11:type=private;id=${URIKEYID}"
ECCRTURI="pkcs11:type=cert;object=${ECCRTN}"

KEYID='0003'
URIKEYID="%00%03"
ECPEERCRTN="ecPeerCert"

ptool --keypairgen --key-type="EC:secp256r1" --id="$KEYID" \
      --label="$ECPEERCRTN" 2>&1
crt_selfsign $ECPEERCRTN "My Peer EC Cert" $KEYID

ECPEERBASEURIWITHPINVALUE="pkcs11:id=${URIKEYID}?pin-value=${PINVALUE}"
ECPEERBASEURIWITHPINSOURCE="pkcs11:id=${URIKEYID}?pin-source=file:${PINFILE}"
ECPEERBASEURI="pkcs11:id=${URIKEYID}"
ECPEERPUBURI="pkcs11:type=public;id=${URIKEYID}"
ECPEERPRIURI="pkcs11:type=private;id=${URIKEYID}"
ECPEERCRTURI="pkcs11:type=cert;object=${ECPEERCRTN}"

title LINE "EC PKCS11 URIS"
echo "${ECBASEURIWITHPINVALUE}"
echo "${ECBASEURIWITHPINSOURCE}"
echo "${ECBASEURI}"
echo "${ECPUBURI}"
echo "${ECPRIURI}"
echo "${ECCRTURI}"
echo "${ECPEERBASEURIWITHPINVALUE}"
echo "${ECPEERBASEURIWITHPINSOURCE}"
echo "${ECPEERBASEURI}"
echo "${ECPEERPUBURI}"
echo "${ECPEERPRIURI}"
echo "${ECPEERCRTURI}"
echo ""


## Softtokn does not support edwards curves yet
if [ "${SUPPORT_ED25519}" -eq 1 ]; then
    # generate ED25519
    KEYID='0004'
    URIKEYID="%00%04"
    EDCRTN="edCert"

    ptool --keypairgen --key-type="EC:edwards25519" --id="$KEYID" \
    	  --label="${EDCRTN}" 2>&1
    ca_sign $EDCRTN "My ED25519 Cert" $KEYID

    EDBASEURIWITHPINVALUE="pkcs11:id=${URIKEYID};pin-value=${PINVALUE}"
    EDBASEURIWITHPINSOURCE="pkcs11:id=${URIKEYID};pin-source=file:${PINFILE}"
    EDBASEURI="pkcs11:id=${URIKEYID}"
    EDPUBURI="pkcs11:type=public;id=${URIKEYID}"
    EDPRIURI="pkcs11:type=private;id=${URIKEYID}"
    EDCRTURI="pkcs11:type=cert;object=${EDCRTN}"

    title LINE "ED25519 PKCS11 URIS"
    echo "${EDBASEURIWITHPINVALUE}"
    echo "${EDBASEURIWITHPINSOURCE}"
    echo "${EDBASEURI}"
    echo "${EDPUBURI}"
    echo "${EDPRIURI}"
    echo "${EDCRTURI}"
fi

if [ "${SUPPORT_ED448}" -eq 1 ]; then
    # generate ED448
    KEYID='0009'
    URIKEYID="%00%09"
    ED2CRTN="ed2Cert"

    ptool --keypairgen --key-type="EC:Ed448" --id="$KEYID" \
          --label="${ED2CRTN}" 2>&1
    ca_sign $ED2CRTN "My ED448 Cert" $KEYID

    ED2BASEURIWITHPINVALUE="pkcs11:id=${URIKEYID};pin-value=${PINVALUE}"
    ED2BASEURIWITHPINSOURCE="pkcs11:id=${URIKEYID};pin-source=file:${PINFILE}"
    ED2BASEURI="pkcs11:id=${URIKEYID}"
    ED2PUBURI="pkcs11:type=public;id=${URIKEYID}"
    ED2PRIURI="pkcs11:type=private;id=${URIKEYID}"
    ED2CRTURI="pkcs11:type=cert;object=${ED2CRTN}"

    title LINE "ED448 PKCS11 URIS"
    echo "${ED2BASEURIWITHPINVALUE}"
    echo "${ED2BASEURIWITHPINSOURCE}"
    echo "${ED2BASEURI}"
    echo "${ED2PUBURI}"
    echo "${ED2PRIURI}"
    echo "${ED2CRTURI}"
fi

title PARA "generate RSA key pair, self-signed certificate, remove public key"
KEYID='0005'
URIKEYID="%00%05"
TSTCRTN="testCert2"

ptool --keypairgen --key-type="RSA:2048" --id="$KEYID" \
      --label="${TSTCRTN}" 2>&1
ca_sign $TSTCRTN "My Test Cert 2" $KEYID
ptool --delete-object --type pubkey --id 0005 2>&1

BASE2URIWITHPINVALUE="pkcs11:id=${URIKEYID}?pin-value=${PINVALUE}"
BASE2URIWITHPINSOURCE="pkcs11:id=${URIKEYID}?pin-source=${PINFILE}"
BASE2URI="pkcs11:id=${URIKEYID}"
PRI2URI="pkcs11:type=private;id=${URIKEYID}"
CRT2URI="pkcs11:type=cert;object=${TSTCRTN}"

title LINE "RSA2 PKCS11 URIS"
echo "${BASE2URIWITHPINVALUE}"
echo "${BASE2URIWITHPINSOURCE}"
echo "${BASE2URI}"
echo "${PRI2URI}"
echo "${CRT2URI}"
echo ""

title PARA "generate EC key pair, self-signed certificate, remove public key"
KEYID='0006'
URIKEYID="%00%06"
TSTCRTN="ecCert2"

ptool --keypairgen --key-type="EC:secp384r1" --id="$KEYID" \
      --label="${TSTCRTN}" 2>&1
ca_sign $TSTCRTN "My EC Cert 2" $KEYID
ptool --delete-object --type pubkey --id 0006 2>&1

ECBASE2URIWITHPINVALUE="pkcs11:id=${URIKEYID}?pin-value=${PINVALUE}"
ECBASE2URIWITHPINSOURCE="pkcs11:id=${URIKEYID}?pin-source=file${PINFILE}"
ECBASE2URI="pkcs11:id=${URIKEYID}"
ECPRI2URI="pkcs11:type=private;id=${URIKEYID}"
ECCRT2URI="pkcs11:type=cert;object=${TSTCRTN}"

title LINE "EC2 PKCS11 URIS"
echo "${ECBASE2URIWITHPINVALUE}"
echo "${ECBASE2URIWITHPINSOURCE}"
echo "${ECBASE2URI}"
echo "${ECPRI2URI}"
echo "${ECCRT2URI}"
echo ""

if [ -z "${ENABLE_EXPLICIT_EC_TEST}" ]; then
    title PARA "explicit EC unsupported"
elif [ "${TOKENTYPE}" == "softokn" ]; then
    title PARA "explicit EC unsupported with softokn"
else
    title PARA "generate explicit EC key pair"
    KEYID='0007'
    URIKEYID="%00%07"
    ECXCRTN="ecExplicitCert"

    ptool --write-object="${TESTSSRCDIR}/explicit_ec.key.der" --type=privkey \
          --id="$KEYID" --label="${ECXCRTN}" --usage-sign --usage-derive 2>&1
    ptool --write-object="${TESTSSRCDIR}/explicit_ec.pub.der" --type=pubkey \
          --id="$KEYID" --label="${ECXCRTN}" --usage-sign --usage-derive 2>&1

    ECXBASEURIWITHPINVALUE="pkcs11:id=${URIKEYID}?pin-value=${PINVALUE}"
    ECXBASEURIWITHPINSOURCE="pkcs11:id=${URIKEYID}?pin-source=file:${PINFILE}"
    ECXBASEURI="pkcs11:id=${URIKEYID}"
    ECXPUBURI="pkcs11:type=public;id=${URIKEYID}"
    ECXPRIURI="pkcs11:type=private;id=${URIKEYID}"

    title LINE "EXPLICIT EC PKCS11 URIS"
    echo "${ECXBASEURI}"
    echo "${ECXPUBURI}"
    echo "${ECXPRIURI}"
    echo ""
fi

title PARA "generate EC key pair with ALWAYS AUTHENTICATE flag, self-signed certificate"
KEYID='0008'
URIKEYID="%00%08"
TSTCRTN="ecCert3"

ptool --keypairgen --key-type="EC:secp521r1" --id="$KEYID" \
      --label="${TSTCRTN}" --always-auth 2>&1
ca_sign $TSTCRTN "My EC Cert 3" $KEYID

ECBASE3URIWITHPINVALUE="pkcs11:id=${URIKEYID}?pin-value=${PINVALUE}"
ECBASE3URIWITHPINSOURCE="pkcs11:id=${URIKEYID}?pin-source=file:${PINFILE}"
ECBASE3URI="pkcs11:id=${URIKEYID}"
ECPUB3URI="pkcs11:type=public;id=${URIKEYID}"
ECPRI3URI="pkcs11:type=private;id=${URIKEYID}"
ECCRT3URI="pkcs11:type=cert;object=${TSTCRTN}"

title LINE "EC3 PKCS11 URIS"
echo "${ECBASE3URIWITHPINVALUE}"
echo "${ECBASE3URIWITHPINSOURCE}"
echo "${ECBASE3URI}"
echo "${ECPUB3URI}"
echo "${ECPRI3URI}"
echo "${ECCRT3URI}"
echo ""

if [ "${SUPPORT_ALLOWED_MECHANISMS}" -eq 1 ]; then
    # generate unrestricted RSA-PSS key pair and RSA-PSS certificate
    KEYID='0010'
    URIKEYID="%00%10"
    TSTCRTN="testRsaPssCert"
    MECHS="RSA-PKCS-PSS"
    MECHS+=",SHA1-RSA-PKCS-PSS,SHA224-RSA-PKCS-PSS"
    MECHS+=",SHA256-RSA-PKCS-PSS,SHA384-RSA-PKCS-PSS,SHA512-RSA-PKCS-PSS"

    ptool --keypairgen --key-type="RSA:2048" --id="$KEYID" \
          --label="${TSTCRTN}" --allowed-mechanisms "$MECHS" 2>&1
    ca_sign "${TSTCRTN}" "My RsaPss Cert" $KEYID "PSS"

    RSAPSSBASEURIWITHPINVALUE="pkcs11:id=${URIKEYID}?pin-value=${PINVALUE}"
    RSAPSSBASEURIWITHPINSOURCE="pkcs11:id=${URIKEYID}?pin-source=file:${PINFILE}"
    RSAPSSBASEURI="pkcs11:id=${URIKEYID}"
    RSAPSSPUBURI="pkcs11:type=public;id=${URIKEYID}"
    RSAPSSPRIURI="pkcs11:type=private;id=${URIKEYID}"
    RSAPSSCRTURI="pkcs11:type=cert;object=${TSTCRTN}"

    title LINE "RSA-PSS PKCS11 URIS"
    echo "${RSAPSSBASEURIWITHPINVALUE}"
    echo "${RSAPSSBASEURIWITHPINSOURCE}"
    echo "${RSAPSSBASEURI}"
    echo "${RSAPSSPUBURI}"
    echo "${RSAPSSPRIURI}"
    echo "${RSAPSSCRTURI}"
    echo ""

    # generate RSA-PSS (3k) key pair restricted to SHA256 digests
    # and RSA-PSS certificate
    KEYID='0011'
    URIKEYID="%00%11"
    TSTCRTN="testRsaPss2Cert"
    MECHS="SHA256-RSA-PKCS-PSS"

    ptool --keypairgen --key-type="RSA:3092" --id="$KEYID" \
          --label="${TSTCRTN}" --allowed-mechanisms "$MECHS" 2>&1
    ca_sign "${TSTCRTN}" "My RsaPss2 Cert" $KEYID "PSS-SHA256"

    RSAPSS2BASEURIWITHPINVALUE="pkcs11:id=${URIKEYID}?pin-value=${PINVALUE}"
    RSAPSS2BASEURIWITHPINSOURCE="pkcs11:id=${URIKEYID}?pin-source=file:${PINFILE}"
    RSAPSS2BASEURI="pkcs11:id=${URIKEYID}"
    RSAPSS2PUBURI="pkcs11:type=public;id=${URIKEYID}"
    RSAPSS2PRIURI="pkcs11:type=private;id=${URIKEYID}"
    RSAPSS2CRTURI="pkcs11:type=cert;object=${TSTCRTN}"

    title LINE "RSA-PSS 2 PKCS11 URIS"
    echo "${RSAPSS2BASEURIWITHPINVALUE}"
    echo "${RSAPSS2BASEURIWITHPINSOURCE}"
    echo "${RSAPSS2BASEURI}"
    echo "${RSAPSS2PUBURI}"
    echo "${RSAPSS2PRIURI}"
    echo "${RSAPSS2CRTURI}"
    echo ""
fi

if [ "$SUPPORT_ML_DSA" -eq 1 ]; then
    title PARA "generate ML-DSA Key pair"
    KEYID='0012'
    URIKEYID="%00%12"
    TSTCRTN="mlDsa"

    # not supported by the pkcs11-tool yet. Do it for now with OpenSSL CLI
    # ptool --keypairgen --key-type="ML-DSA-44" --id="$KEYID" \
    #       --label="${TSTCRTN}" 2>&1
    ORIG_OPENSSL_CONF=${OPENSSL_CONF}
    # We need to configure pkcs11 to allow emitting PEM URIs so that the
    # genpkey command does not fail on trying to emit the private key PEM file.
    sed -e "s/#pkcs11-module-encode-provider-uri-to-pem/pkcs11-module-encode-provider-uri-to-pem = true/" \
        "${OPENSSL_CONF}" > "${OPENSSL_CONF}.mldsa_pem_uri"
    OPENSSL_CONF=${OPENSSL_CONF}.mldsa_pem_uri
    ossl '
    genpkey -propquery "provider=pkcs11"
            -algorithm ML-DSA-44
            -pkeyopt "pkcs11_uri:pkcs11:object=${TSTCRTN};id=${URIKEYID}"'
    OPENSSL_CONF=${ORIG_OPENSSL_CONF}
    ca_sign $TSTCRTN "My ML-DSA Cert" $KEYID

    MLDSABASEURIWITHPINVALUE="pkcs11:id=${URIKEYID}?pin-value=${PINVALUE}"
    MLDSABASEURIWITHPINSOURCE="pkcs11:id=${URIKEYID}?pin-source=file:${PINFILE}"
    MLDSABASEURI="pkcs11:id=${URIKEYID}"
    MLDSAPUBURI="pkcs11:type=public;id=${URIKEYID}"
    MLDSAPRIURI="pkcs11:type=private;id=${URIKEYID}"
    MLDSACRTURI="pkcs11:type=cert;object=${TSTCRTN}"

    title LINE "ML-DSA PKCS11 URIS"
    echo "${MLDSABASEURI}"
    echo "${MLDSAPUBURI}"
    echo "${MLDSAPRIURI}"
    echo "${MLDSACRTURI}"
    echo ""
fi


title PARA "Show contents of ${TOKENTYPE} token"
echo " ----------------------------------------------------------------------------------------------------"
ptool -O
echo " ----------------------------------------------------------------------------------------------------"

title LINE "Export test variables to ${TMPPDIR}/testvars"
cat >> "${TMPPDIR}/testvars" <<DBGSCRIPT
${TOKENCONFIGVARS}
export P11LIB="${P11LIB}"
export TOKENTYPE="${TOKENTYPE}"
export TOKENLABEL="${TOKENLABEL}"
export PKCS11_PROVIDER_MODULE=${P11LIB}
export PPDBGFILE=${TMPPDIR}/p11prov-debug.log
export PKCS11_PROVIDER_DEBUG="file:${TMPPDIR}/p11prov-debug.log"
export OPENSSL_CONF="${OPENSSL_CONF}"
export TESTSSRCDIR="${TESTSSRCDIR}"
export TESTBLDDIR="${TESTBLDDIR}"

export SUPPORT_ED25519="${SUPPORT_ED25519}"
export SUPPORT_ED448="${SUPPORT_ED448}"
export SUPPORT_ML_DSA="${SUPPORT_ML_DSA}"
export SUPPORT_RSA_PKCS1_ENCRYPTION="${SUPPORT_RSA_PKCS1_ENCRYPTION}"
export SUPPORT_RSA_KEYGEN_PUBLIC_EXPONENT="${SUPPORT_RSA_KEYGEN_PUBLIC_EXPONENT}"
export SUPPORT_TLSFUZZER="${SUPPORT_TLSFUZZER}"
export SUPPORT_ALLOWED_MECHANISMS="${SUPPORT_ALLOWED_MECHANISMS}"
export SUPPORT_SKEY="${SUPPORT_SKEY}"
export SUPPORT_SYMMETRIC="${SUPPORT_SYMMETRIC}"

export TESTPORT="${TESTPORT}"

export TOKDIR="${TOKDIR}"
export TMPPDIR="${TMPPDIR}"
export PINVALUE="${PINVALUE}"
export SEEDFILE="${TMPPDIR}/noisefile.bin"
export RAND64FILE="${TMPPDIR}/64krandom.bin"

export CACRT="${CACRT_PEM}"
export CABASEURIWITHPINVALUE="${CABASEURIWITHPINVALUE}"
export CABASEURIWITHPINSOURCE="${CABASEURIWITHPINSOURCE}"
export CABASEURI="${CABASEURI}"
export CAPUBURI="${CAPUBURI}"
export CAPRIURI="${CAPRIURI}"
export CACRTURI="${CACRTURI}"

export BASEURIWITHPINVALUE="${BASEURIWITHPINVALUE}"
export BASEURIWITHPINSOURCE="${BASEURIWITHPINSOURCE}"
export BASEURI="${BASEURI}"
export PUBURI="${PUBURI}"
export PRIURI="${PRIURI}"
export CRTURI="${CRTURI}"

export ECBASEURIWITHPINVALUE="${ECBASEURIWITHPINVALUE}"
export ECBASEURIWITHPINSOURCE="${ECBASEURIWITHPINSOURCE}"
export ECBASEURI="${ECBASEURI}"
export ECPUBURI="${ECPUBURI}"
export ECPRIURI="${ECPRIURI}"
export ECCRTURI="${ECCRTURI}"

export ECPEERBASEURIWITHPINVALUE="${ECPEERBASEURIWITHPINVALUE}"
export ECPEERBASEURIWITHPINSOURCE="${ECPEERBASEURIWITHPINSOURCE}"
export ECPEERBASEURI="${ECPEERBASEURI}"
export ECPEERPUBURI="${ECPEERPUBURI}"
export ECPEERPRIURI="${ECPEERPRIURI}"
export ECPEERCRTURI="${ECPEERCRTURI}"

export BASE2URIWITHPINVALUE="${BASEURIWITHPINVALUE}"
export BASE2URIWITHPINSOURCE="${BASEURIWITHPINSOURCE}"
export BASE2URI="${BASE2URI}"
export PRI2URI="${PRI2URI}"
export CRT2URI="${CRT2URI}"

export ECBASE2URIWITHPINVALUE="${ECBASE2URIWITHPINVALUE}"
export ECBASE2URIWITHPINSOURCE="${ECBASE2URIWITHPINSOURCE}"
export ECBASE2URI="${ECBASE2URI}"
export ECPRI2URI="${ECPRI2URI}"
export ECCRT2URI="${ECCRT2URI}"

export ECBASE3URIWITHPINVALUE="${ECBASE3URIWITHPINVALUE}"
export ECBASE3URIWITHPINSOURCE="${ECBASE3URIWITHPINSOURCE}"
export ECBASE3URI="${ECBASE3URI}"
export ECPUB3URI="${ECPUB3URI}"
export ECPRI3URI="${ECPRI3URI}"
export ECCRT3URI="${ECCRT3URI}"
DBGSCRIPT

if [ -n "${EDBASEURI}" ]; then
    cat >> "${TMPPDIR}/testvars" <<DBGSCRIPT

export EDBASEURIWITHPINVALUE="${EDBASEURIWITHPINVALUE}"
export EDBASEURIWITHPINSOURCE="${EDBASEURIWITHPINSOURCE}"
export EDBASEURI="${EDBASEURI}"
export EDPUBURI="${EDPUBURI}"
export EDPRIURI="${EDPRIURI}"
export EDCRTURI="${EDCRTURI}"
DBGSCRIPT
fi

if [ -n "${ED2BASEURI}" ]; then
    cat >> "${TMPPDIR}/testvars" <<DBGSCRIPT

export ED2BASEURIWITHPINVALUE="${ED2BASEURIWITHPINVALUE}"
export ED2BASEURIWITHPINSOURCE="${ED2BASEURIWITHPINSOURCE}"
export ED2BASEURI="${ED2BASEURI}"
export ED2PUBURI="${ED2PUBURI}"
export ED2PRIURI="${ED2PRIURI}"
export ED2CRTURI="${ED2CRTURI}"
DBGSCRIPT
fi

if [ -n "${ECXBASEURI}" ]; then
    cat >> "${TMPPDIR}/testvars" <<DBGSCRIPT

export ECXBASEURIWITHPINVALUE="${ECXBASEURIWITHPINVALUE}"
export ECXBASEURIWITHPINSOURCE="${ECXBASEURIWITHPINSOURCE}"
export ECXBASEURI="${ECXBASEURI}"
export ECXPUBURI="${ECXPUBURI}"
export ECXPRIURI="${ECXPRIURI}"
DBGSCRIPT
fi

if [ -n "${RSAPSSBASEURI}" ]; then
    cat >> "${TMPPDIR}/testvars" <<DBGSCRIPT

export RSAPSSBASEURIWITHPINVALUE="${RSAPSSBASEURIWITHPINVALUE}"
export RSAPSSBASEURIWITHPINSOURCE="${RSAPSSBASEURIWITHPINSOURCE}"
export RSAPSSBASEURI="${RSAPSSBASEURI}"
export RSAPSSPUBURI="${RSAPSSPUBURI}"
export RSAPSSPRIURI="${RSAPSSPRIURI}"
export RSAPSSCRTURI="${RSAPSSCRTURI}"

export RSAPSS2BASEURIWITHPINVALUE="${RSAPSS2BASEURIWITHPINVALUE}"
export RSAPSS2BASEURIWITHPINSOURCE="${RSAPSS2BASEURIWITHPINSOURCE}"
export RSAPSS2BASEURI="${RSAPSS2BASEURI}"
export RSAPSS2PUBURI="${RSAPSS2PUBURI}"
export RSAPSS2PRIURI="${RSAPSS2PRIURI}"
export RSAPSS2CRTURI="${RSAPSS2CRTURI}"
DBGSCRIPT
fi

if [ -n "${MLDSABASEURI}" ]; then
    cat >> "${TMPPDIR}/testvars" <<DBGSCRIPT

export MLDSABASEURIWITHPINVALUE="${MLDSABASEURIWITHPINVALUE}"
export MLDSABASEURIWITHPINSOURCE="${MLDSABASEURIWITHPINSOURCE}"
export MLDSABASEURI="${MLDSABASEURI}"
export MLDSAPUBURI="${MLDSAPUBURI}"
export MLDSAPRIURI="${MLDSAPRIURI}"
export MLDSACRTURI="${MLDSACRTURI}"
DBGSCRIPT
fi

cat >> "${TMPPDIR}/testvars" <<DBGSCRIPT

# for listing the separate pkcs11 calls
#export PKCS11SPY="${P11LIB}"
#export PKCS11_PROVIDER_MODULE=/usr/lib64/pkcs11-spy.so
DBGSCRIPT

if [ -n "${OPENSSL_FORCE_FIPS_MODE}" ]; then
    cat >> "${TMPPDIR}/testvars" <<DBGSCRIPT
export OPENSSL_FORCE_FIPS_MODE=1
DBGSCRIPT
fi

if [ -n "${NSS_FIPS}" ]; then
    cat >> "${TMPPDIR}/testvars" <<DBGSCRIPT
export NSS_FIPS=1
DBGSCRIPT
fi

gen_unsetvars

title ENDSECTION

