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

# Ed448 requires OpenSC 0.26.0, which is not available in Ubuntu and CentOS 9
if [[ -f /etc/debian_version ]] && grep Ubuntu /etc/lsb-release; then
    SUPPORT_ED448=0
elif [[ -f /etc/redhat-release ]] && grep "release 9" /etc/redhat-release; then
    SUPPORT_ED448=0
fi

# FIPS Mode
if [[ "${OPENSSL_FORCE_FIPS_MODE}" = "1" || "$(cat /proc/sys/crypto/fips_enabled)" = "1" ]]; then
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
fi

# Temporary dir and Token data dir
TMPPDIR="${TESTBLDDIR}/${TOKENTYPE}"
TOKDIR="$TMPPDIR/tokens"
if [ -d "${TMPPDIR}" ]; then
    rm -fr "${TMPPDIR}"
fi
mkdir "${TMPPDIR}"
mkdir "${TOKDIR}"

PINVALUE="12345678"
PINFILE="${TMPPDIR}/pinfile.txt"
echo ${PINVALUE} > "${PINFILE}"
export GNUTLS_PIN=$PINVALUE

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

#RANDOM data
SEEDFILE="${TMPPDIR}/noisefile.bin"
dd if=/dev/urandom of="${SEEDFILE}" bs=2048 count=1 >/dev/null 2>&1
RAND64FILE="${TMPPDIR}/64krandom.bin"
dd if=/dev/urandom of="${RAND64FILE}" bs=2048 count=32 >/dev/null 2>&1

# On macOS, /usr/bin/certtool is a different program. Both MacPorts and
# Homebrew rename GnuTLS' certtool to gnutls-certtool, so check for that first.
#
# https://github.com/macports/macports-ports/blob/4494b720a4807ddfc18bddf876620a5c6b24ce4f/devel/gnutls/Portfile#L206-L209
# https://github.com/Homebrew/homebrew-core/blob/83be349adb47980b4046258b74fa8c1e99ca96a3/Formula/gnutls.rb#L56-L58
if [ "$(uname)" == "Darwin" ]; then
    certtool=$(type -p gnutls-certtool)
else
    certtool=$(type -p certtool)
fi
if [ -z "$certtool" ]; then
    echo "Missing GnuTLS certtool (on macOS, commonly installed as gnutls-certtool)"
    exit 0
fi

# NSS uses the second slot for certificates, so we need to provide the token
# label in the args to allow pkcs11-tool to find the right slot
P11DEFARGS=("--module=${P11LIB}" "--login" "--pin=${PINVALUE}" "--token-label=${TOKENLABEL}")

# prepare certtool configuration
cat >> "${TMPPDIR}/cacert.cfg" <<HEREDOC
ca
cn = "Issuer"
serial = 1
expiration_days = 365
email = "testcert@example.org"
signing_key
encryption_key
cert_signing_key
HEREDOC

# Serial = 1 is the CA
SERIAL=1

crt_selfsign() {
    LABEL=$1
    CN=$2
    KEYID=$3
    ((SERIAL+=1))
    sed -e "s|cn = .*|cn = $CN|g" \
        -e "s|serial = .*|serial = $SERIAL|g" \
        "${sed_inplace[@]}" "${TMPPDIR}/cacert.cfg"
    "${certtool}" --generate-self-signed --outfile="${TMPPDIR}/${LABEL}.crt" \
        --template="${TMPPDIR}/cacert.cfg" --provider="$P11LIB" \
	--load-privkey "pkcs11:object=$LABEL;token=$TOKENLABELURI;type=private" \
        --load-pubkey "pkcs11:object=$LABEL;token=$TOKENLABELURI;type=public" --outder 2>&1
    pkcs11-tool "${P11DEFARGS[@]}" --write-object "${TMPPDIR}/${LABEL}.crt" --type=cert \
        --id="$KEYID" --label="$LABEL" 2>&1
}

title LINE "Creating new Self Sign CA"
KEYID='0000'
URIKEYID="%00%00"
CACRTN="caCert"
pkcs11-tool "${P11DEFARGS[@]}" --keypairgen --key-type="RSA:2048" \
	--label="${CACRTN}" --id="${KEYID}" 2>&1
crt_selfsign $CACRTN "Issuer" $KEYID

# convert the DER cert to PEM
CACRT_PEM="${TMPPDIR}/${CACRTN}.pem"
CACRT="${TMPPDIR}/${CACRTN}.crt"
openssl x509 -inform DER -in "$CACRT" -outform PEM -out "$CACRT_PEM"

cat "${TMPPDIR}/cacert.cfg" > "${TMPPDIR}/cert.cfg"
# the organization identification is not in the CA
echo 'organization = "PKCS11 Provider"' >> "${TMPPDIR}/cert.cfg"
# the cert_signing_key and "ca" should be only on the CA
sed -e "/^cert_signing_key$/d" -e "/^ca$/d" "${sed_inplace[@]}" "${TMPPDIR}/cert.cfg"

ca_sign() {
    LABEL=$1
    CN=$2
    KEYID=$3
    ((SERIAL+=1))
    sed -e "s|cn = .*|cn = $CN|g" \
        -e "s|serial = .*|serial = $SERIAL|g" \
        -e "/^ca$/d" \
        "${sed_inplace[@]}" \
        "${TMPPDIR}/cert.cfg"
    "${certtool}" --generate-certificate --outfile="${TMPPDIR}/${LABEL}.crt" \
        --template="${TMPPDIR}/cert.cfg" --provider="$P11LIB" \
	--load-privkey "pkcs11:object=$LABEL;token=$TOKENLABELURI;type=private" \
        --load-pubkey "pkcs11:object=$LABEL;token=$TOKENLABELURI;type=public" --outder \
        --load-ca-certificate "${CACRT}" --inder \
        --load-ca-privkey="pkcs11:object=$CACRTN;token=$TOKENLABELURI;type=private"
    pkcs11-tool "${P11DEFARGS[@]}" --write-object "${TMPPDIR}/${LABEL}.crt" --type=cert \
        --id="$KEYID" --label="$LABEL" 2>&1
}


# generate RSA key pair and self-signed certificate
KEYID='0001'
URIKEYID="%00%01"
TSTCRTN="testCert"

pkcs11-tool "${P11DEFARGS[@]}" --keypairgen --key-type="RSA:2048" \
	--label="${TSTCRTN}" --id="$KEYID"
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

pkcs11-tool "${P11DEFARGS[@]}" --keypairgen --key-type="EC:secp256r1" \
	--label="${ECCRTN}" --id="$KEYID"
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

pkcs11-tool "${P11DEFARGS[@]}" --keypairgen --key-type="EC:secp256r1" \
	--label="$ECPEERCRTN" --id="$KEYID"
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

    pkcs11-tool "${P11DEFARGS[@]}" --keypairgen --key-type="EC:edwards25519" \
    	--label="${EDCRTN}" --id="$KEYID"
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

    pkcs11-tool "${P11DEFARGS[@]}" --keypairgen --key-type="EC:Ed448" \
        --label="${ED2CRTN}" --id="$KEYID"
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

pkcs11-tool "${P11DEFARGS[@]}" --keypairgen --key-type="RSA:2048" \
	--label="${TSTCRTN}" --id="$KEYID"
ca_sign $TSTCRTN "My Test Cert 2" $KEYID
pkcs11-tool "${P11DEFARGS[@]}" --delete-object --type pubkey --id 0005

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

pkcs11-tool "${P11DEFARGS[@]}" --keypairgen --key-type="EC:secp384r1" \
	--label="${TSTCRTN}" --id="$KEYID"
ca_sign $TSTCRTN "My EC Cert 2" $KEYID
pkcs11-tool "${P11DEFARGS[@]}" --delete-object --type pubkey --id 0006

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

    pkcs11-tool "${P11DEFARGS[@]}" --write-object="${TESTSSRCDIR}/explicit_ec.key.der" --type=privkey \
        --label="${ECXCRTN}" --id="$KEYID"
    pkcs11-tool "${P11DEFARGS[@]}" --write-object="${TESTSSRCDIR}/explicit_ec.pub.der" --type=pubkey \
        --label="${ECXCRTN}" --id="$KEYID"

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

pkcs11-tool "${P11DEFARGS[@]}" --keypairgen --key-type="EC:secp521r1" \
	--label="${TSTCRTN}" --id="$KEYID" --always-auth
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

title PARA "Show contents of ${TOKENTYPE} token"
echo " ----------------------------------------------------------------------------------------------------"
pkcs11-tool "${P11DEFARGS[@]}" -O
echo " ----------------------------------------------------------------------------------------------------"

title PARA "Output configurations"
OPENSSL_CONF=${TMPPDIR}/openssl.cnf

title LINE "Generate openssl config file"
sed -e "s|@libtoollibs@|${LIBSPATH}|g" \
    -e "s|@testsblddir@|${TESTBLDDIR}|g" \
    -e "s|@testsdir@|${TMPPDIR}|g" \
    -e "s|@SHARED_EXT@|${SHARED_EXT}|g" \
    -e "s|@PINFILE@|${PINFILE}|g" \
    -e "s|##TOKENOPTIONS|${TOKENOPTIONS}|g" \
    "${TESTSSRCDIR}/openssl.cnf.in" > "${OPENSSL_CONF}"

title LINE "Export test variables to ${TMPPDIR}/testvars"
cat >> "${TMPPDIR}/testvars" <<DBGSCRIPT
${TOKENCONFIGVARS}
export P11LIB="${P11LIB}"
export TOKENLABEL="${TOKENLABEL}"
export PKCS11_PROVIDER_MODULE=${P11LIB}
export PPDBGFILE=${TMPPDIR}/p11prov-debug.log
export PKCS11_PROVIDER_DEBUG="file:${TMPPDIR}/p11prov-debug.log"
export OPENSSL_CONF="${OPENSSL_CONF}"
export TESTSSRCDIR="${TESTSSRCDIR}"
export TESTBLDDIR="${TESTBLDDIR}"

export SUPPORT_ED25519="${SUPPORT_ED25519}"
export SUPPORT_ED448="${SUPPORT_ED448}"
export SUPPORT_RSA_PKCS1_ENCRYPTION="${SUPPORT_RSA_PKCS1_ENCRYPTION}"
export SUPPORT_RSA_KEYGEN_PUBLIC_EXPONENT="${SUPPORT_RSA_KEYGEN_PUBLIC_EXPONENT}"
export SUPPORT_TLSFUZZER="${SUPPORT_TLSFUZZER}"

export TESTPORT="${TESTPORT}"

export CACRT="${CACRT_PEM}"

export TOKDIR="${TOKDIR}"
export TMPPDIR="${TMPPDIR}"
export PINVALUE="${PINVALUE}"
export SEEDFILE="${TMPPDIR}/noisefile.bin"
export RAND64FILE="${TMPPDIR}/64krandom.bin"

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

cat >> "${TMPPDIR}/testvars" <<DBGSCRIPT

# for listing the separate pkcs11 calls
#export PKCS11SPY="${P11LIB}"
#export PKCS11_PROVIDER_MODULE=/usr/lib64/pkcs11-spy.so
DBGSCRIPT
gen_unsetvars

title ENDSECTION

