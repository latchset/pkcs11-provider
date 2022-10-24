#!/bin/bash

########### generic ###########
title() {
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

ossl() {
    echo r $* >> ${GDB_CMDS}

    echo openssl $*

    eval openssl $1
    return $?
}

skip() {
    title LINE "skip"
    return 77
}

log_test_result() {
    local rc=$1
    local name=$2
    local subn=$3
    local mesg=$4

    case "${rc}" in
    "0")
        echo "* TESTCASE ${name} ${subn} PASS ${mesg}" >> ${RESULTLOG}
        ;;
    "77")
        echo "* TESTCASE ${name} ${subn} SKIP ${mesg}" >> ${RESULTLOG}
        ;;
    *)
        echo "* TESTCASE ${name} ${subn} FAIL ${mesg}" >> ${RESULTLOG}
        ;;
    esac
}

########### openssl-specific ###########

if [ -z "${TMPDIR}" -o \
     ! -d "${TMPDIR}" -o \
     -z "${OPENSSL_CONF}" ]; then
     echo "skip (requirements missing)"
     exit 77
fi

GDB_CMDS=${TMPDIR}/gdb_commands.txt
> ${GDB_CMDS}
RESULTLOG=${TMPDIR}/result.log
> ${RESULTLOG}

title PARA "RSA key export"

title LINE "export public key to file"
if [ -n "${PUBURI}" ]; then
    ossl '
    pkey -in ${PUBURI} -pubin -pubout -out ${BASEFILE}.pub'
else
    skip
fi
log_test_result $? "RSA" "key-export" "export public key to file"

title LINE "export private key to file (failure expected)"
if [ -n "${PRIURI}" ]; then
    ! ossl '
    pkey -in ${PRIURI} -out ${BASEFILE}.pem' 2> /dev/null
else
    skip
fi
log_test_result $? "RSA" "key-export" "export private key to file (failure expected)"

title PARA "RSA en-/decrypt data"

echo "secret test" > ${TMPDIR}/secret.txt

title LINE "encrypt data with public key (file)"
if [ -f "${BASEFILE}.pub" ]; then
    ossl '
    pkeyutl -encrypt
            -inkey "${BASEFILE}.pub"
            -pubin
            -pkeyopt pad-mode:oaep
            -pkeyopt digest:sha256
            -pkeyopt mgf1-digest:sha256
            -in ${TMPDIR}/secret.txt
            -out ${TMPDIR}/secret.txt.enc'
else
    skip
fi
log_test_result $? "RSA" "encrypt" "encrypt data (file)"

title LINE "decrypt data with private key"
if [ -n "${PRIURI}" ]; then
    ossl '
    pkeyutl -decrypt
            -inkey "${PRIURI}"
            -pkeyopt pad-mode:oaep
            -pkeyopt digest:sha256
            -pkeyopt mgf1-digest:sha256
            -in ${TMPDIR}/secret.txt.enc
            -out ${TMPDIR}/secret.txt.dec'
else
    skip
fi
log_test_result $? "RSA" "decrypt" "decrypt data data (URI)"

diff -q ${TMPDIR}/secret.txt ${TMPDIR}/secret.txt.dec
log_test_result $? "RSA" "en-decrypt" "compare original and decrypted text"

title PARA "RSA sign/verify data"

title LINE "sign data with private key"
if [ -n "${PRIURI}" ]; then
    ossl '
    pkeyutl -sign -digest sha256
            -inkey ${PRIURI}
            -in ${R64K} -rawin
            -out ${R64K}_rsa.sig'
else
    skip
fi
log_test_result $? "RSA" "sign" "sign data (URI)"

title LINE "verify signature with public key (URI)"
if [ -n "${PUBURI}" ]; then
    ossl '
    pkeyutl -verify -digest sha256
            -inkey ${PUBURI} -pubin
            -in ${R64K} -rawin
            -sigfile ${R64K}_rsa.sig'
else
    skip
fi
log_test_result $? "RSA" "verify" "verify data (URI)"

title LINE "verify signature with public key (file)"
if [ -f "${BASEFILE}.pub" ]; then
    ossl '
    pkeyutl -verify -digest sha256
            -inkey ${BASEFILE}.pub -pubin
            -in ${R64K} -rawin
            -sigfile ${R64K}_rsa.sig'
else
    skip
fi
log_test_result $? "RSA" "verify" "verify data (URI)"

title PARA "EC key export"

title LINE "export public key to file"
if [ -n "${ECPUBURI}" ]; then
    ossl '
    pkey -in ${ECPUBURI} -pubin -pubout -out ${ECBASEFILE}.pub'
else
    skip
fi
log_test_result $? "EC" "key-export" "export public key to file"

title LINE "export private key to file (failure expected)"
if [ -n "${PRIURI}" ]; then
    ! ossl '
    pkey -in ${ECPRIURI} -out ${ECBASEFILE}.pem' 2> /dev/null
else
    skip
fi
log_test_result $? "EC" "key-export" "export private key to file (failure expected)"

title PARA "EC sign/verify data (ECDSA)"

title LINE "sign data with private key"
if [ -n "${ECPRIURI}" ]; then
    ossl '
    pkeyutl -sign -digest sha256
            -inkey ${ECPRIURI}
            -in ${R64K} -rawin
            -out ${R64K}_ec.sig'
else
    skip
fi
log_test_result $? "EC" "sign" "sign data (URI)"

title LINE "verify signature with public key (URI)"
if [ -n "${ECPUBURI}" ]; then
    ossl '
    pkeyutl -verify -digest sha256
            -inkey ${ECPUBURI} -pubin
            -in ${R64K} -rawin
            -sigfile ${R64K}_ec.sig'
else
    skip
fi
log_test_result $? "EC" "verify" "verify data (URI)"

title LINE "verify signature with public key (file)"
if [ -f "${ECBASEFILE}.pub" ]; then
    ossl '
    pkeyutl -verify -digest sha256
            -inkey ${ECBASEFILE}.pub -pubin
            -in ${R64K} -rawin
            -sigfile ${R64K}_ec.sig'
else
    skip
fi
log_test_result $? "EC" "verify" "verify data (file)"

cat ${RESULTLOG}
echo done
