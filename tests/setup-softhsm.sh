#!/bin/bash -e
# Copyright (C) 2022 Jakub Jelen <jjelen@redhat.com>
# SPDX-License-Identifier: Apache-2.0

source ${TESTSSRCDIR}/helpers.sh

if ! command -v softhsm2-util &> /dev/null
then
    echo "SoftHSM is is required"
    exit 0
fi

# On macOS, /usr/bin/certtool is a different program. Both MacPorts and
# Homebrew rename GnuTLS' certtool to gnutls-certtool, so check for that first.
#
# https://github.com/macports/macports-ports/blob/4494b720a4807ddfc18bddf876620a5c6b24ce4f/devel/gnutls/Portfile#L206-L209
# https://github.com/Homebrew/homebrew-core/blob/83be349adb47980b4046258b74fa8c1e99ca96a3/Formula/gnutls.rb#L56-L58
if [ "$(uname)" == "Darwin" ]; then
    certtool=$(type -p gnutls-certtool)
else
    certtool=$(type -p certtool)
    sed_backup=""
fi
if [ -z "$certtool" ]; then
    echo "Missing GnuTLS certtool (on macOS, commonly installed as gnutls-certtool)"
    exit 0
fi

# macOS uses BSD sed, which expects the argument after -i (with a space after
# it!) to be the backup suffix, while GNU sed expects a potential backup suffix
# directly after -i and interprets -i <expression> as in-place editing with no
# backup.
#
# Use "${sed_inplace[@]}" to make that work transparently by setting it to the
# arguments required to achieve in-place editing without backups depending on
# the version of sed.
if sed --version 2>/dev/null | grep -q 'GNU sed'; then
	sed_inplace=("-i")
else
	sed_inplace=("-i" "")
fi

if [ "$P11KITCLIENTPATH" = "" ]; then
    echo "Missing P11KITCLIENTPATH env variable"
    exit 0
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
    exit 0
}

title SECTION "Searching for SoftHSM PKCS#11 library"
# Attempt to guess the path to libsofthsm2.so relative to that. This fixes
# auto-detection on platforms such as macOS with MacPorts (and potentially
# Homebrew).
#
# This should never be empty, since we checked for the presence of
# softhsm2-util above and use it below.

# Strip bin/softhsm2-util
softhsm_prefix=$(dirname "$(dirname "$(type -p softhsm2-util)")")

find_softhsm \
    "$softhsm_prefix/lib64/softhsm/libsofthsm2.so" \
    "$softhsm_prefix/lib/softhsm/libsofthsm2.so" \
    "$softhsm_prefix/lib64/pkcs11/libsofthsm2.so" \
    "$softhsm_prefix/lib/pkcs11/libsofthsm2.so" \
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

# prepare certtool configuration
cat >> ${TMPPDIR}/cert.cfg <<HEREDOC
ca
cn = "Issuer"
serial = 1
expiration_days = 365
email = "testcert@example.org"
signing_key
encryption_key
HEREDOC
export GNUTLS_PIN=$PINVALUE
SERIAL=1

# init
softhsm2-util --init-token --label "token_name" --free --pin $PINVALUE --so-pin $PINVALUE

title LINE "Creating new Self Sign CA"
KEYID='0000'
URIKEYID="%00%00"
CACRT="${TMPPDIR}/CAcert"
CACRTN="caCert"
let "SERIAL+=1"
pkcs11-tool --keypairgen --key-type="RSA:2048" --login --pin=$PINVALUE --module="$P11LIB" \
	--label="${CACRTN}" --id="$KEYID"
"${certtool}" --generate-self-signed --outfile="${CACRT}.crt" --template=${TMPPDIR}/cert.cfg \
        --provider="$P11LIB" --load-privkey "pkcs11:object=$CACRTN;type=private" \
        --load-pubkey "pkcs11:object=$CACRTN;type=public" --outder
pkcs11-tool --write-object "${CACRT}.crt" --type=cert --id=$KEYID \
        --label="$CACRTN" --module="$P11LIB"

# the organization identification is not in the CA
echo 'organization = "PKCS11 Provider"' >> ${TMPPDIR}/cert.cfg

ca_sign() {
    CRT=$1
    LABEL=$2
    CN=$3
    KEYID=$4
    let "SERIAL+=1"
    sed -e "s|cn = .*|cn = $CN|g" \
        -e "s|serial = .*|serial = $SERIAL|g" \
        -e "/^ca$/d" \
        "${sed_inplace[@]}" \
        "${TMPPDIR}/cert.cfg"
    "${certtool}" --generate-certificate --outfile="${CRT}.crt" --template=${TMPPDIR}/cert.cfg \
        --provider="$P11LIB" --load-privkey "pkcs11:object=$LABEL;type=private" \
        --load-pubkey "pkcs11:object=$LABEL;type=public" --outder \
        --load-ca-certificate "${CACRT}.crt" --inder \
        --load-ca-privkey="pkcs11:object=$CACRTN;type=private"
    pkcs11-tool --write-object "${CRT}.crt" --type=cert --id=$KEYID \
        --label="$LABEL" --module="$P11LIB"

}


# generate RSA key pair and self-signed certificate
KEYID='0001'
URIKEYID="%00%01"
TSTCRT="${TMPPDIR}/testcert"
TSTCRTN="testCert"

pkcs11-tool --keypairgen --key-type="RSA:2048" --login --pin=$PINVALUE --module="$P11LIB" \
	--label="${TSTCRTN}" --id="$KEYID"
ca_sign $TSTCRT $TSTCRTN "My Test Cert" $KEYID

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

# generate ECC key pair
KEYID='0002'
URIKEYID="%00%02"
ECCRT="${TMPPDIR}/eccert"
ECCRTN="ecCert"

pkcs11-tool --keypairgen --key-type="EC:secp256r1" --login --pin=$PINVALUE --module="$P11LIB" \
	--label="${ECCRTN}" --id="$KEYID"
ca_sign $ECCRT $ECCRTN "My EC Cert" $KEYID

ECBASEURIWITHPIN="pkcs11:id=${URIKEYID};pin-value=${PINVALUE}"
ECBASEURI="pkcs11:id=${URIKEYID}"
ECPUBURI="pkcs11:type=public;id=${URIKEYID}"
ECPRIURI="pkcs11:type=private;id=${URIKEYID}"
ECCRTURI="pkcs11:type=cert;object=${ECCRTN}"

KEYID='0003'
URIKEYID="%00%03"
ECPEERCRT="${TMPPDIR}/ecpeercert"
ECPEERCRTN="ecPeerCert"

pkcs11-tool --keypairgen --key-type="EC:secp256r1" --login --pin=$PINVALUE --module="$P11LIB" \
	--label="$ECPEERCRTN" --id="$KEYID"
ca_sign $ECPEERCRT $ECPEERCRTN "My Peer EC Cert" $KEYID

ECPEERBASEURIWITHPIN="pkcs11:id=${URIKEYID};pin-value=${PINVALUE}"
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
echo "${ECPEERBASEURIWITHPIN}"
echo "${ECPEERBASEURI}"
echo "${ECPEERPUBURI}"
echo "${ECPEERPRIURI}"
echo "${ECPEERCRTURI}"
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
    -e "s|@testssrcdir[@]|${BASEDIR}|g" \
    -e "s|@testsblddir@|${TESTBLDDIR}|g" \
    -e "s|@SHARED_EXT@|${SHARED_EXT}|g" \
    -e "/pkcs11-module-init-args/d" \
    ${TESTSSRCDIR}/openssl.cnf.in > ${OPENSSL_CONF}

title LINE "Export test variables to ${TMPPDIR}/testvars"
cat >> ${TMPPDIR}/testvars <<DBGSCRIPT
export P11LIB=${P11LIB}
export P11KITCLIENTPATH=${P11KITCLIENTPATH}
export PKCS11_PROVIDER_MODULE=${P11LIB}
export PKCS11_PROVIDER_DEBUG="file:${BASEDIR}/${TMPPDIR}/p11prov-debug.log"
export OPENSSL_CONF="${OPENSSL_CONF}"
export SOFTHSM2_CONF=${BASEDIR}/${TMPPDIR}/softhsm.conf
export TESTSSRCDIR="${TESTSSRCDIR}"

export TOKDIR="${BASEDIR}/${TOKDIR}"
export TMPPDIR="${BASEDIR}/${TMPPDIR}"
export PINVALUE="${PINVALUE}"
export SEEDFILE="${BASEDIR}/${TMPPDIR}/noisefile.bin"
export RAND64FILE="${BASEDIR}/${TMPPDIR}/64krandom.bin"

export BASEURIWITHPIN="${BASEURIWITHPIN}"
export BASEURI="${BASEURI}"
export PUBURI="${PUBURI}"
export PRIURI="${PRIURI}"
export CRTURI="${CRTURI}"
export ECBASEURI="${ECBASEURI}"
export ECPUBURI="${ECPUBURI}"
export ECPRIURI="${ECPRIURI}"
export ECCRTURI="${ECCRTURI}"
export ECPEERBASEURI="${ECPEERBASEURI}"
export ECPEERPUBURI="${ECPEERPUBURI}"
export ECPEERPRIURI="${ECPEERPRIURI}"
export ECPEERCRTURI="${ECPEERCRTURI}"

# for listing the separate pkcs11 calls
#export PKCS11SPY="${PKCS11_PROVIDER_MODULE}"
#export PKCS11_PROVIDER_MODULE=/usr/lib64/pkcs11-spy.so
DBGSCRIPT
gen_unsetvars

title ENDSECTION
