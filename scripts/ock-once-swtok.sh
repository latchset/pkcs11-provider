#!/bin/bash

PIN=${OCK_PIN:-"12345678"}

if id -u | grep -qw 0 && groups | grep -qwv pkcs11 ; then
    echo "missing pkcs11 group membership"
    exit 77
fi

if ! command -v pkcsslotd > /dev/null; then
    echo "pkcsslotd is required"
    exit 77
fi

for PREFIX in "/usr/local/" "/" "NA"; do
    if [ "$PREFIX" = "NA" ]; then
        echo "No ock configuration found or ock-swtok not configured"
        exit 77
    fi

    OCK_CONF=${PREFIX}etc/opencryptoki/opencryptoki.conf
    SLOT=$(grep -B2 "^stdll = libpkcs11_sw.so$" ${OCK_CONF} 2> /dev/null | grep -Po "slot \K[^\s]+")
    test -n "${SLOT}" && break
done

if [ $(id -u) != "0" ]; then
    echo "skip restart of pkcsslotd (require UID 0)"
else
    killall pkcsslotd > /dev/null 2>&1
    pkcsslotd || exit 99
fi

PID=$(pidof pkcsslotd)
if [ -z "${PID}" ]; then
    echo "pkcsslotd not running"
    exit 77
fi

echo "pkcsslotd running (PID: ${PID})"
echo "configuration: ${OCK_CONF}"
echo "swtok configured on slot ${SLOT}"

if [ "$1" != "--batch" ]; then
    echo    "*******************************************************************************"
    echo    "*** This script may rename the swtok and may destroy existing key material in"
    echo -n "*** this token. Please confirm to continue [y|N]: "
    read CONFIRM
    echo    "*******************************************************************************"

    if [ "${CONFIRM}" != "y" -a "${CONFIRM}" != "Y" ]; then
        echo "abort!"
        exit 77
    fi
fi

if ! $(pkcsconf -t -c ${SLOT} | grep -q "Flags: .*TOKEN_INITIALIZED.*"); then
    echo "slot ${SLOT}: initialize token"
    echo "test" | pkcsconf -c ${SLOT} -I -S "87654321" > /dev/null \
    || exit 99
fi

if $(pkcsconf -t -c ${SLOT} | grep -q "Flags: .*SO_PIN_TO_BE_CHANGED.*"); then
    echo "slot ${SLOT}: set new so-pin (76543210)"
    pkcsconf -c ${SLOT} -P -S "87654321" -n "76543210" \
    || exit 99
fi

if ! $(pkcsconf -t -c ${SLOT} | grep -q "Flags: .*USER_PIN_INITIALIZED.*"); then
    echo "slot ${SLOT}: set new user-pin (${PIN})"
    pkcsconf -c ${SLOT} -u -S "76543210" -n "${PIN}" \
    || exit 99
fi

exit 0
